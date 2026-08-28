import json
import re
from contextlib import suppress
from pathlib import Path
from typing import Any

import psutil
import requests
import validators
from cryptography import x509
from django.conf import settings
from django.core.cache import cache
from django.db import IntegrityError
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from django.views.decorators.csrf import csrf_exempt
from redis import from_url
from rest_framework import serializers
from rest_framework import status as drf_status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from core.decorators import monitoring_view, monitoring_view_v2
from core.tasks import sync_mesh_perms_task
from core.utils import (
    get_core_settings,
    run_server_script,
    run_test_url_rest_action,
    sysd_svc_is_running,
    token_is_valid,
)
from qdt_mcp.executor import execute_mcp_tool, is_read_only_tool, list_mcp_tools
from logs.models import AuditLog
from tacticalrmm.constants import AuditActionType, PAStatus
from tacticalrmm.helpers import get_certs, notify_error
from tacticalrmm.logger import logger
from tacticalrmm.permissions import (
    _has_perm,
    _has_perm_on_agent,
    _has_perm_on_client,
    _has_perm_on_site,
)

from .models import (
    AIChatMessage,
    AIChatSession,
    CodeSignToken,
    CoreSettings,
    CustomField,
    GlobalKVStore,
    Schedule,
    URLAction,
)
from .permissions import (
    CodeSignPerms,
    CoreSettingsPerms,
    CustomFieldPerms,
    GlobalKeyStorePerms,
    RunServerScriptPerms,
    SchedulePerms,
    ServerMaintPerms,
    URLActionPerms,
    WebTerminalPerms,
)
from .serializers import (
    AIChatSessionSerializer,
    CodeSignTokenSerializer,
    CoreSettingsSerializer,
    CustomFieldSerializer,
    KeyStoreSerializer,
    ScheduleSerializer,
    URLActionSerializer,
)


class GetEditCoreSettings(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def get(self, request):
        settings = CoreSettings.objects.first()
        return Response(CoreSettingsSerializer(settings).data)

    def put(self, request):
        data = request.data.copy()

        if getattr(settings, "HOSTED", False):
            data.pop("mesh_site")
            data.pop("mesh_token")
            data.pop("mesh_username")
            data["sync_mesh_with_trmm"] = True
            data["enable_server_scripts"] = False
            data["enable_server_webterminal"] = False

        coresettings = CoreSettings.objects.first()
        serializer = CoreSettingsSerializer(
            instance=coresettings, data=data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        sync_mesh_perms_task.delay()

        return Response("ok")


@api_view()
@permission_classes([AllowAny])
def home(request):
    return Response({"status": "ok"})


@api_view()
def version(request):
    return Response(settings.APP_VER)


@api_view()
@permission_classes([IsAuthenticated, ServerMaintPerms])
def clear_cache(request):
    from core.utils import clear_entire_cache

    clear_entire_cache()
    return Response("Cache was cleared!")


@api_view()
def dashboard_info(request):
    if request.user.is_installer_user:
        return notify_error("")

    from core.utils import token_is_expired
    from tacticalrmm.utils import get_latest_trmm_ver, runcmd_placeholder_text

    core_settings = get_core_settings()
    return Response(
        {
            "trmm_version": settings.TRMM_VERSION,
            "latest_trmm_ver": get_latest_trmm_ver(),
            "dark_mode": request.user.dark_mode,
            "show_community_scripts": request.user.show_community_scripts,
            "dbl_click_action": request.user.agent_dblclick_action,
            "default_agent_tbl_tab": request.user.default_agent_tbl_tab,
            "url_action": (
                request.user.url_action.id if request.user.url_action else None
            ),
            "client_tree_sort": request.user.client_tree_sort,
            "client_tree_splitter": request.user.client_tree_splitter,
            "loading_bar_color": request.user.loading_bar_color,
            "clear_search_when_switching": request.user.clear_search_when_switching,
            "hosted": getattr(settings, "HOSTED", False),
            "date_format": request.user.date_format,
            "default_date_format": core_settings.date_format,
            "token_is_expired": token_is_expired(),
            "open_ai_integration_enabled": bool(
                core_settings.open_ai_token or core_settings.minimax_token
            ),
            "ai_provider": core_settings.ai_provider,
            "dash_info_color": request.user.dash_info_color,
            "dash_positive_color": request.user.dash_positive_color,
            "dash_negative_color": request.user.dash_negative_color,
            "dash_warning_color": request.user.dash_warning_color,
            "run_cmd_placeholder_text": runcmd_placeholder_text(),
            "server_scripts_enabled": core_settings.server_scripts_enabled,
            "web_terminal_enabled": core_settings.web_terminal_enabled,
            "block_local_user_logon": core_settings.block_local_user_logon,
            "sso_enabled": core_settings.sso_enabled,
        }
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated, CoreSettingsPerms])
def email_test(request):
    core = get_core_settings()

    msg, ok = core.send_mail(
        subject="Test from Tactical RMM", body="This is a test message", test=True
    )
    if not ok:
        return notify_error(msg)

    return Response(msg)


@api_view(["POST"])
@permission_classes([IsAuthenticated, ServerMaintPerms])
def server_maintenance(request):
    from tacticalrmm.utils import reload_nats

    if "action" not in request.data:
        return notify_error("The data is incorrect")

    if request.data["action"] == "reload_nats":
        reload_nats()
        return Response("Nats configuration was reloaded successfully.")

    if request.data["action"] == "rm_orphaned_tasks":
        from autotasks.tasks import remove_orphaned_win_tasks

        remove_orphaned_win_tasks.delay()
        return Response("The task has been initiated.")

    if request.data["action"] == "prune_db":
        from logs.models import AuditLog, PendingAction

        if "prune_tables" not in request.data:
            return notify_error("The data is incorrect.")

        tables = request.data["prune_tables"]
        records_count = 0
        if "audit_logs" in tables:
            auditlogs = AuditLog.objects.filter(action=AuditActionType.CHECK_RUN)
            records_count += auditlogs.count()
            auditlogs.delete()

        if "pending_actions" in tables:
            pendingactions = PendingAction.objects.filter(status=PAStatus.COMPLETED)
            records_count += pendingactions.count()
            pendingactions.delete()

        if "alerts" in tables:
            from alerts.models import Alert

            alerts = Alert.objects.all()
            records_count += alerts.count()
            alerts.delete()

        return Response(f"{records_count} records were pruned from the database")

    return notify_error("The data is incorrect")


class GetAddCustomFields(APIView):
    permission_classes = [IsAuthenticated, CustomFieldPerms]

    def get(self, request):
        if "model" in request.query_params.keys():
            fields = CustomField.objects.filter(model=request.query_params["model"])
        else:
            fields = CustomField.objects.all()
        return Response(CustomFieldSerializer(fields, many=True).data)

    def patch(self, request):
        if "model" in request.data.keys():
            fields = CustomField.objects.filter(model=request.data["model"])
            return Response(CustomFieldSerializer(fields, many=True).data)

        return notify_error("The request was invalid")

    def post(self, request):
        serializer = CustomFieldSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response("ok")


class GetUpdateDeleteCustomFields(APIView):
    permission_classes = [IsAuthenticated, CustomFieldPerms]

    def get(self, request, pk):
        custom_field = get_object_or_404(CustomField, pk=pk)

        return Response(CustomFieldSerializer(custom_field).data)

    def put(self, request, pk):
        custom_field = get_object_or_404(CustomField, pk=pk)

        serializer = CustomFieldSerializer(
            instance=custom_field, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response("ok")

    def delete(self, request, pk):
        get_object_or_404(CustomField, pk=pk).delete()

        return Response("ok")


class CodeSign(APIView):
    permission_classes = [IsAuthenticated, CodeSignPerms]

    def get(self, request):
        token = CodeSignToken.objects.first()
        return Response(CodeSignTokenSerializer(token).data)

    def patch(self, request):
        import requests

        token = request.data["token"].strip().replace(" ", "").lower()
        if not validators.uuid(token):
            return notify_error("Invalid token format.")

        try:
            r = requests.post(
                settings.CHECK_TOKEN_URL,
                json={"token": token, "api": settings.ALLOWED_HOSTS[0]},
                headers={"Content-type": "application/json"},
                timeout=15,
            )
        except Exception as e:
            return notify_error(str(e))

        if r.status_code in (400, 401):
            return notify_error(r.json()["ret"])
        elif r.status_code == 200:
            t = CodeSignToken.objects.first()
            if t is None:
                CodeSignToken.objects.create(token=token)
            else:
                t.token = token
                t.save(update_fields=["token"])
            return Response("Token was saved")

        try:
            ret = r.json()["ret"]
        except:
            ret = "Something went wrong"
        return notify_error(ret)

    def post(self, request):
        from agents.models import Agent
        from agents.tasks import send_agent_update_task

        token, is_valid = token_is_valid()
        if not is_valid:
            return notify_error("Invalid token")

        agent_ids: list[str] = list(
            Agent.objects.only("pk", "agent_id").values_list("agent_id", flat=True)
        )
        send_agent_update_task.delay(agent_ids=agent_ids, token=token, force=True)
        return Response("Agents will be code signed shortly")

    def delete(self, request):
        CodeSignToken.objects.all().delete()
        return Response("ok")


class GetAddKeyStore(APIView):
    permission_classes = [IsAuthenticated, GlobalKeyStorePerms]

    def get(self, request):
        keys = GlobalKVStore.objects.all()
        return Response(KeyStoreSerializer(keys, many=True).data)

    def post(self, request):
        serializer = KeyStoreSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response("ok")


class UpdateDeleteKeyStore(APIView):
    permission_classes = [IsAuthenticated, GlobalKeyStorePerms]

    def put(self, request, pk):
        key = get_object_or_404(GlobalKVStore, pk=pk)

        serializer = KeyStoreSerializer(instance=key, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response("ok")

    def delete(self, request, pk):
        get_object_or_404(GlobalKVStore, pk=pk).delete()

        return Response("ok")


class GetAddURLAction(APIView):
    permission_classes = [IsAuthenticated, URLActionPerms]

    def get(self, request):
        actions = URLAction.objects.all()
        return Response(URLActionSerializer(actions, many=True).data)

    def post(self, request):
        serializer = URLActionSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response("ok")


class UpdateDeleteURLAction(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def put(self, request, pk):
        action = get_object_or_404(URLAction, pk=pk)

        serializer = URLActionSerializer(
            instance=action, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response("ok")

    def delete(self, request, pk):
        get_object_or_404(URLAction, pk=pk).delete()

        return Response("ok")


class RunURLAction(APIView):
    permission_classes = [IsAuthenticated, URLActionPerms]

    def patch(self, request):
        from requests.utils import requote_uri

        from agents.models import Agent
        from clients.models import Client, Site
        from tacticalrmm.utils import RE_DB_VALUE, get_db_value

        if "agent_id" in request.data.keys():
            if not _has_perm_on_agent(request.user, request.data["agent_id"]):
                raise PermissionDenied()

            instance = get_object_or_404(Agent, agent_id=request.data["agent_id"])
        elif "site" in request.data.keys():
            if not _has_perm_on_site(request.user, request.data["site"]):
                raise PermissionDenied()

            instance = get_object_or_404(Site, pk=request.data["site"])
        elif "client" in request.data.keys():
            if not _has_perm_on_client(request.user, request.data["client"]):
                raise PermissionDenied()

            instance = get_object_or_404(Client, pk=request.data["client"])
        else:
            return notify_error("received an incorrect request")

        action = get_object_or_404(URLAction, pk=request.data["action"])

        url_pattern = action.pattern

        for string, model, prop in RE_DB_VALUE.findall(url_pattern):
            value = get_db_value(string=f"{model}.{prop}", instance=instance)

            url_pattern = url_pattern.replace(string, str(value))

        AuditLog.audit_url_action(
            username=request.user.username,
            urlaction=action,
            instance=instance,
            debug_info={"ip": request._client_ip},
        )

        return Response(requote_uri(url_pattern))


class RunTestURLAction(APIView):
    permission_classes = [IsAuthenticated, URLActionPerms]

    class InputSerializer(serializers.Serializer):
        pattern = serializers.CharField(required=True)
        rest_body = serializers.CharField()
        rest_headers = serializers.CharField()
        rest_method = serializers.ChoiceField(
            required=True, choices=["get", "post", "put", "delete", "patch"]
        )
        run_instance_type = serializers.ChoiceField(
            choices=["agent", "client", "site", "none"]
        )
        run_instance_id = serializers.CharField(allow_null=True)

    def post(self, request):
        serializer = self.InputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        url = serializer.validated_data.get("pattern")
        body = serializer.validated_data.get("rest_body", None)
        headers = serializer.validated_data.get("rest_headers", None)
        method = serializer.validated_data.get("rest_method")
        instance_type = serializer.validated_data.get("run_instance_type", None)
        instance_id = serializer.validated_data.get("run_instance_id", None)

        # make sure user has permissions to run against client/agent/site
        if instance_type == "agent":
            if not _has_perm_on_agent(request.user, instance_id):
                raise PermissionDenied()

        elif instance_type == "site":
            if not _has_perm_on_site(request.user, instance_id):
                raise PermissionDenied()

        elif instance_type == "client":
            if not _has_perm_on_client(request.user, instance_id):
                raise PermissionDenied()

        result, replaced_url, replaced_body = run_test_url_rest_action(
            url=url,
            body=body,
            headers=headers,
            method=method,
            instance_type=instance_type,
            instance_id=instance_id,
        )

        AuditLog.audit_url_action_test(
            username=request.user.username,
            url=url,
            body=replaced_body,
            headers=headers,
            instance_type=instance_type,
            instance_id=instance_id,
            debug_info={"ip": request._client_ip},
        )

        return Response({"url": replaced_url, "result": result, "body": replaced_body})


class GetAddSchedule(APIView):
    permission_classes = [IsAuthenticated, SchedulePerms]

    def get(self, request):
        schedules = Schedule.objects.all()
        return Response(ScheduleSerializer(schedules, many=True).data)

    def post(self, request):
        serializer = ScheduleSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data)


class UpdateDeleteSchedule(APIView):
    permission_classes = [IsAuthenticated, SchedulePerms]

    def put(self, request, pk):
        schedule = get_object_or_404(Schedule, pk=pk)

        serializer = ScheduleSerializer(
            instance=schedule, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data)

    def delete(self, request, pk):
        schedule = get_object_or_404(Schedule, pk=pk)

        try:
            schedule.delete()
        except IntegrityError:
            return notify_error("This schedule is currently in use.")

        return Response(pk)


class TestRunServerScript(APIView):
    permission_classes = [IsAuthenticated, RunServerScriptPerms]

    def post(self, request):
        core: CoreSettings = CoreSettings.objects.first()  # type: ignore
        if not core.server_scripts_enabled:
            return notify_error(
                "This feature is disabled. It can be enabled in Global Settings."
            )

        code: str = request.data["code"]
        if not code.startswith("#!"):
            return notify_error("Missing shebang!")

        stdout, stderr, execution_time, retcode = run_server_script(
            body=code,
            args=request.data["args"],
            env_vars=request.data["env_vars"],
            timeout=request.data["timeout"],
            shell=request.data["shell"],
        )

        ret = {
            "stdout": stdout,
            "stderr": stderr,
            "execution_time": f"{execution_time:.4f}",
            "retcode": retcode,
        }

        audit_before = {
            "body": code,
            "args": request.data["args"],
            "env_vars": request.data["env_vars"],
            "timeout": request.data["timeout"],
            "shell": request.data["shell"],
        }

        AuditLog.audit_test_script_run(
            username=request.user.username,
            before_value=audit_before,
            after_value=ret,
            agent=None,
            debug_info={"ip": request._client_ip},
        )

        return Response(ret)


@api_view(["POST"])
@permission_classes([IsAuthenticated, WebTerminalPerms])
def webterm_perms(request):
    # this view is only used to display a notification if feature is disabled
    # perms are actually enforced in the consumer
    core: CoreSettings = CoreSettings.objects.first()  # type: ignore
    if not core.web_terminal_enabled:
        ret = "This feature is disabled. It can be enabled in Global Settings."
        return Response(ret, status=drf_status.HTTP_412_PRECONDITION_FAILED)

    return Response("ok")


class TwilioSMSTest(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def post(self, request):
        core = get_core_settings()
        if not core.sms_is_configured:
            return notify_error(
                "All fields are required, including at least 1 recipient"
            )

        msg, ok = core.send_sms("TacticalRMM Test SMS", test=True)
        if not ok:
            return notify_error(msg)

        return Response(msg)


@csrf_exempt
@monitoring_view_v2
def status_v2(request):
    from agents.models import Agent
    from clients.models import Client, Site
    from tacticalrmm.helpers import get_nats_ports
    from tacticalrmm.utils import get_celery_queue_len, localhost_port_is_open

    disk_usage: int = round(psutil.disk_usage("/").percent)
    mem_usage: int = round(psutil.virtual_memory().percent)

    cert_file, _ = get_certs()
    cert_bytes = Path(cert_file).read_bytes()

    cert = x509.load_pem_x509_certificate(cert_bytes)
    delta = cert.not_valid_after_utc - djangotime.now()

    redis_url = f"redis://{settings.REDIS_HOST}"
    redis_ping = False
    with suppress(Exception):
        with from_url(redis_url) as conn:
            conn.ping()
            redis_ping = True

    celery_queue_health = "healthy"
    try:
        queue_len = get_celery_queue_len()
    except RuntimeError as e:
        queue_len = -1
        celery_queue_health = "unhealthy"
        logger.error(f"Error getting celery queue length: {e}")

    nats_std_port, nats_ws_port = get_nats_ports()
    mesh_port = getattr(settings, "MESH_PORT", 4430)

    ret = {
        "version": settings.TRMM_VERSION,
        "latest_agent_version": settings.LATEST_AGENT_VER,
        "agent_count": Agent.objects.count(),
        "client_count": Client.objects.count(),
        "site_count": Site.objects.count(),
        "disk_usage_percent": disk_usage,
        "mem_usage_percent": mem_usage,
        "days_until_cert_expires": delta.days,
        "cert_expired": delta.days < 0,
        "redis_ping": redis_ping,
        "celery_queue_len": queue_len,
        "celery_queue_health": celery_queue_health,
        "nats_std_ping": localhost_port_is_open(nats_std_port),
        "nats_ws_ping": localhost_port_is_open(nats_ws_port),
        "mesh_ping": localhost_port_is_open(mesh_port),
        "services_running": {
            "mesh": sysd_svc_is_running("meshcentral.service"),
            "daphne": sysd_svc_is_running("daphne.service"),
            "celery": sysd_svc_is_running("celery.service"),
            "celerybeat": sysd_svc_is_running("celerybeat.service"),
            "redis": sysd_svc_is_running("redis-server.service"),
            "nats": sysd_svc_is_running("nats.service"),
            "nats-api": sysd_svc_is_running("nats-api.service"),
        },
    }

    return JsonResponse(ret, json_dumps_params={"indent": 2})


# TODO deprecated
@csrf_exempt
@monitoring_view
def status(request):
    from agents.models import Agent
    from clients.models import Client, Site

    disk_usage: int = round(psutil.disk_usage("/").percent)
    mem_usage: int = round(psutil.virtual_memory().percent)

    cert_file, _ = get_certs()
    cert_bytes = Path(cert_file).read_bytes()

    cert = x509.load_pem_x509_certificate(cert_bytes)
    delta = cert.not_valid_after_utc - djangotime.now()

    redis_url = f"redis://{settings.REDIS_HOST}"
    redis_ping = False
    with suppress(Exception):
        with from_url(redis_url) as conn:
            conn.ping()
            redis_ping = True

    ret = {
        "version": settings.TRMM_VERSION,
        "latest_agent_version": settings.LATEST_AGENT_VER,
        "agent_count": Agent.objects.count(),
        "client_count": Client.objects.count(),
        "site_count": Site.objects.count(),
        "disk_usage_percent": disk_usage,
        "mem_usage_percent": mem_usage,
        "days_until_cert_expires": delta.days,
        "cert_expired": delta.days < 0,
        "redis_ping": redis_ping,
    }

    if settings.DOCKER_BUILD:
        ret["services_running"] = "not available in docker"
    else:
        ret["services_running"] = {
            "django": sysd_svc_is_running("rmm.service"),
            "mesh": sysd_svc_is_running("meshcentral.service"),
            "daphne": sysd_svc_is_running("daphne.service"),
            "celery": sysd_svc_is_running("celery.service"),
            "celerybeat": sysd_svc_is_running("celerybeat.service"),
            "redis": sysd_svc_is_running("redis-server.service"),
            "postgres": sysd_svc_is_running("postgresql.service"),
            "mongo": sysd_svc_is_running("mongod.service"),
            "nats": sysd_svc_is_running("nats.service"),
            "nats-api": sysd_svc_is_running("nats-api.service"),
            "nginx": sysd_svc_is_running("nginx.service"),
        }
    return JsonResponse(ret, json_dumps_params={"indent": 2})


class OpenAICodeCompletion(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        settings = get_core_settings()

        if settings.ai_provider == "minimax":
            api_url = "https://api.minimax.io/v1/chat/completions"
            token = settings.minimax_token
            model = settings.minimax_model
            provider_label = "MiniMax"
        else:
            api_url = "https://api.openai.com/v1/chat/completions"
            token = settings.open_ai_token
            model = settings.open_ai_model
            provider_label = "Open AI"

        if not token:
            return notify_error(
                f"{provider_label} API Key not found. Open Global Settings > Open AI."
            )

        # messages allows the script manager to send a full back-and-forth
        # conversation for iterative refinement; prompt stays supported for
        # the single-shot "Generate Script" button
        messages = request.data.get("messages")
        if not messages:
            if not request.data.get("prompt"):
                return notify_error("Not prompt field found")
            messages = [{"role": "user", "content": request.data["prompt"]}]

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }

        data = {
            "messages": messages,
            "model": model,
            "temperature": 0.5,
            "max_tokens": 4000,
            "n": 1,
            "stop": None,
        }

        try:
            response = requests.post(
                api_url,
                headers=headers,
                json=data,
                timeout=60,
            )
        except Exception as e:
            return notify_error(str(e))

        try:
            response_data = response.json()
        except ValueError:
            return notify_error(
                f"The {provider_label} API returned an unexpected response (HTTP {response.status_code})"
            )

        if "error" in response_data:
            error = response_data["error"]
            message = error.get("message", error) if isinstance(error, dict) else error
            return notify_error(f"The {provider_label} API returned an error: {message}")

        if not response_data.get("choices"):
            return notify_error(
                f"The {provider_label} API returned no completion (HTTP {response.status_code})"
            )

        return Response(response_data["choices"][0]["message"]["content"])


class AIChatSessions(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        if not _has_perm(request, "can_list_agents"):
            raise PermissionDenied()
        sessions = AIChatSession.objects.filter(user=request.user)
        serializer = AIChatSessionSerializer(
            sessions.order_by("-updated_at"), many=True
        )
        return Response({"sessions": serializer.data})

    def post(self, request: Request) -> Response:
        if not _has_perm(request, "can_list_agents"):
            raise PermissionDenied()
        title = request.data.get("title", "")
        session = AIChatSession.objects.create(user=request.user, title=title)
        serializer = AIChatSessionSerializer(session)
        return Response(serializer.data, status=drf_status.HTTP_201_CREATED)


class AIChatSessionDetail(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request: Request, pk: str) -> Response:
        if not _has_perm(request, "can_list_agents"):
            raise PermissionDenied()
        session = get_object_or_404(AIChatSession, pk=pk, user=request.user)
        serializer = AIChatSessionSerializer(session)
        return Response(serializer.data)

    def delete(self, request: Request, pk: str) -> Response:
        if not _has_perm(request, "can_list_agents"):
            raise PermissionDenied()
        session = get_object_or_404(AIChatSession, pk=pk, user=request.user)
        session.delete()
        return Response("ok")


class AIChatCompletion(APIView):
    """Chat endpoint that can invoke MCP tools through the backend.

    The frontend never talks directly to /mcp and never sees an API key. All
    tool execution happens server-side, gated on Django session authentication.
    """

    permission_classes = [IsAuthenticated]

    MAX_REQUESTS_PER_MINUTE = 30
    MAX_TOOL_CALLS_PER_REQUEST = 10
    MAX_MESSAGE_LENGTH = 4000
    MAX_MESSAGES = 50

    def _rate_limited(self, user_id: int) -> bool:
        # cache-backed so the limit holds across workers, not just per process
        key = f"ai-chat-rate-{user_id}"
        try:
            count = cache.incr(key)
        except ValueError:
            cache.set(key, 1, timeout=60)
            count = 1
        return count > self.MAX_REQUESTS_PER_MINUTE

    def _llm_settings(self):
        settings = get_core_settings()
        if settings.ai_provider == "minimax":
            return {
                "api_url": "https://api.minimax.io/v1/chat/completions",
                "token": settings.minimax_token,
                "model": settings.minimax_model,
                "provider_label": "MiniMax",
            }
        return {
            "api_url": "https://api.openai.com/v1/chat/completions",
            "token": settings.open_ai_token,
            "model": settings.open_ai_model,
            "provider_label": "Open AI",
        }

    def _system_prompt(self) -> str:
        tools = list_mcp_tools()
        tool_descriptions = []
        for tool in tools:
            params = json.dumps(tool["parameters"], indent=2)
            tool_descriptions.append(
                f"- {tool['name']}: {tool['description']}\n  parameters: {params}\n  read_only: {tool['read_only']}"
            )

        return (
            "You are Tactical RMM's AI assistant. You help administrators manage their fleet.\n"
            "You have access to the following tools. To call a tool, output one or more blocks exactly like this:\n"
            "<tool_call>\n"
            '{"name": "TOOL_NAME", "arguments": {"arg1": "value1"}}\n'
            "</tool_call>\n"
            "After you receive tool results, respond to the user with a concise, helpful summary.\n"
            "Do not ask the user for passwords, API keys, or other secrets.\n"
            "For read-only tools you may call them directly. For tools that change state "
            "(run_command, run_script, reboot_agent, kill_process, control_service, run_checks), "
            "you MUST ask the user for confirmation first and output the tool call only after they confirm.\n\n"
            "Available tools:\n" + "\n".join(tool_descriptions)
        )

    def _extract_tool_calls(self, content: str) -> list[dict[str, Any]]:
        pattern = r"<tool_call>\s*(\{.*?\})\s*</tool_call>"
        matches = re.findall(pattern, content, re.DOTALL)
        calls = []
        for raw in matches:
            try:
                parsed = json.loads(raw)
                if "name" in parsed and isinstance(parsed.get("arguments"), dict):
                    calls.append(parsed)
            except json.JSONDecodeError:
                continue
        return calls

    def _strip_tool_calls(self, content: str) -> str:
        return re.sub(r"<tool_call>.*?<\/tool_call>", "", content, flags=re.DOTALL).strip()

    def _call_llm(self, messages: list[dict[str, str]], llm: dict) -> str:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {llm['token']}",
        }
        data = {
            "messages": messages,
            "model": llm["model"],
            "temperature": 0.3,
            "max_tokens": 4000,
            "n": 1,
            "stop": None,
        }
        response = requests.post(
            llm["api_url"],
            headers=headers,
            json=data,
            timeout=120,
        )
        response.raise_for_status()
        response_data = response.json()
        return response_data["choices"][0]["message"]["content"]

    def _execute_and_log(
        self,
        request: Request,
        name: str,
        arguments: dict[str, Any],
        confirmed: bool = False,
    ) -> Any:
        """Execute an MCP tool as the calling user and write an audit log entry."""
        session_id = request.data.get("session_id", "")
        username = request.user.username
        try:
            outcome = execute_mcp_tool(name, arguments, user=request.user)
        except Exception as exc:
            outcome = {"error": str(exc)}
            AuditLog.audit_ai_chat_tool(
                username=username,
                tool_name=name,
                arguments=arguments,
                outcome=outcome,
                session_id=session_id,
                confirmed=confirmed,
            )
            raise

        AuditLog.audit_ai_chat_tool(
            username=username,
            tool_name=name,
            arguments=arguments,
            outcome=outcome,
            session_id=session_id,
            confirmed=confirmed,
        )
        return outcome

    def _get_or_create_session(
        self, request: Request, session_id: str | None
    ) -> AIChatSession:
        if session_id:
            with suppress(AIChatSession.DoesNotExist, ValueError):
                return AIChatSession.objects.get(pk=session_id, user=request.user)

        title = ""
        for msg in reversed(request.data.get("messages", [])):
            if msg.get("role") == "user":
                title = str(msg.get("content", ""))[:100]
                break

        return AIChatSession.objects.create(user=request.user, title=title)

    @staticmethod
    def _was_proposed(session: AIChatSession, confirmed_tool: dict) -> bool:
        """A confirmed tool must be one the assistant actually proposed in this
        session and the user was shown. Otherwise "confirmed" is just a direct
        execution api for whatever the client makes up."""
        last = session.messages.filter(role="assistant").order_by("-id").first()
        pending = (last.tool_calls or {}).get("pending_tool_calls", []) if last else []
        name = confirmed_tool.get("name")
        arguments = confirmed_tool.get("arguments", {})
        return any(
            p.get("name") == name and p.get("arguments", {}) == arguments
            for p in pending
        )

    def _save_chat_turn(
        self,
        session: AIChatSession,
        messages: list[dict[str, str]],
        assistant_content: str,
        executed: list[dict[str, Any]] | None = None,
        pending: list[dict[str, Any]] | None = None,
        final_content: str | None = None,
    ) -> None:
        """Persist the current turn, replacing any previously stored messages."""
        session.messages.all().delete()

        for msg in messages:
            AIChatMessage.objects.create(
                session=session,
                role=msg.get("role", "user"),
                content=msg.get("content", ""),
            )

        tool_calls: dict[str, Any] = {}
        if executed:
            tool_calls["executed_tools"] = executed
        if pending:
            tool_calls["pending_tool_calls"] = pending

        AIChatMessage.objects.create(
            session=session,
            role="assistant",
            content=assistant_content,
            tool_calls=tool_calls or None,
        )

        if final_content:
            AIChatMessage.objects.create(
                session=session,
                role="assistant",
                content=final_content,
            )

    def post(self, request: Request) -> Response:
        # tools run as the calling user, but the feature itself still wants a
        # baseline permission - a role-less account must not reach the LLM at all
        if not _has_perm(request, "can_list_agents"):
            raise PermissionDenied()

        user_id = request.user.id
        if self._rate_limited(user_id):
            return notify_error("Rate limit exceeded: max 30 AI chat requests per minute.")

        messages = request.data.get("messages", [])
        if not isinstance(messages, list):
            return notify_error("messages must be a list")

        if len(messages) > self.MAX_MESSAGES:
            return notify_error(f"Too many messages. Max {self.MAX_MESSAGES} allowed.")

        for msg in messages:
            if len(str(msg.get("content", ""))) > self.MAX_MESSAGE_LENGTH:
                return notify_error(f"Message too long. Max {self.MAX_MESSAGE_LENGTH} characters.")

        # only user/assistant turns may pass through - a client-supplied "system"
        # message would sit in front of the real system prompt
        messages = [
            {"role": msg["role"], "content": str(msg.get("content", ""))}
            for msg in messages
            if isinstance(msg, dict) and msg.get("role") in ("user", "assistant")
        ]

        confirmed_tool = request.data.get("confirmed_tool")
        llm = self._llm_settings()
        if not llm["token"]:
            return notify_error(
                f"{llm['provider_label']} API Key not found. Open Global Settings > Open AI."
            )

        system_prompt = self._system_prompt()
        chat_messages = [{"role": "system", "content": system_prompt}] + messages

        try:
            content = self._call_llm(chat_messages, llm)
        except requests.HTTPError as e:
            return notify_error(f"LLM API error: {e.response.text[:500]}")
        except requests.RequestException as e:
            return notify_error(f"LLM request failed: {str(e)}")

        session = self._get_or_create_session(request, request.data.get("session_id"))

        tool_calls = self._extract_tool_calls(content)
        if not tool_calls:
            self._save_chat_turn(session, messages, content)
            return Response({
                "message": content,
                "executed_tools": [],
                "pending_tool_calls": [],
                "session_id": str(session.pk),
            })

        if len(tool_calls) > self.MAX_TOOL_CALLS_PER_REQUEST:
            return notify_error(f"Too many tool calls. Max {self.MAX_TOOL_CALLS_PER_REQUEST} allowed.")

        executed = []
        pending = []

        # If the frontend confirmed a specific tool, execute only that one - and
        # only if the assistant actually proposed it in this session
        if confirmed_tool and confirmed_tool.get("name"):
            if not self._was_proposed(session, confirmed_tool):
                return notify_error(
                    "this tool call was not proposed in this session"
                )
            name = confirmed_tool["name"]
            arguments = confirmed_tool.get("arguments", {})
            outcome = self._execute_and_log(request, name, arguments, confirmed=True)
            executed.append({"name": name, "arguments": arguments, "outcome": outcome})
            tool_result_message = {
                "role": "user",
                "content": f"Tool '{name}' executed. Result: {json.dumps(outcome)}",
            }
            final_messages = chat_messages + [{"role": "assistant", "content": content}, tool_result_message]
            try:
                final_content = self._call_llm(final_messages, llm)
            except requests.RequestException as e:
                return notify_error(f"LLM request failed: {str(e)}")

            self._save_chat_turn(session, messages, content, executed=executed, final_content=final_content)
            return Response({
                "message": self._strip_tool_calls(final_content),
                "executed_tools": executed,
                "pending_tool_calls": [],
                "session_id": str(session.pk),
            })

        # Otherwise auto-execute read-only tools and ask for confirmation on write tools
        for call in tool_calls:
            name = call["name"]
            arguments = call.get("arguments", {})
            if is_read_only_tool(name):
                outcome = self._execute_and_log(request, name, arguments)
                executed.append({"name": name, "arguments": arguments, "outcome": outcome})
            else:
                pending.append({
                    "name": name,
                    "arguments": arguments,
                    "requires_confirmation": True,
                    "description": f"This will execute the '{name}' tool on the RMM.",
                })

        if pending:
            self._save_chat_turn(session, messages, content, executed=executed, pending=pending)
            return Response({
                "message": self._strip_tool_calls(content),
                "executed_tools": executed,
                "pending_tool_calls": pending,
                "session_id": str(session.pk),
            })

        # All tools were read-only, ask the LLM to summarize the results
        tool_results = [
            {
                "role": "user",
                "content": "Tool results:\n" + json.dumps(executed, indent=2),
            }
        ]
        final_messages = chat_messages + [{"role": "assistant", "content": content}] + tool_results
        try:
            final_content = self._call_llm(final_messages, llm)
        except requests.RequestException as e:
            return notify_error(f"LLM request failed: {str(e)}")

        self._save_chat_turn(session, messages, content, executed=executed, final_content=final_content)
        return Response({
            "message": self._strip_tool_calls(final_content),
            "executed_tools": executed,
            "pending_tool_calls": [],
            "session_id": str(session.pk),
        })
