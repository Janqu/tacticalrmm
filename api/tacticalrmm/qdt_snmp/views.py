import asyncio
import datetime as dt
import json
import logging
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from clients.models import Site
from core.serializers import mask_token
from logs.models import AuditLog
from tacticalrmm.helpers import notify_error
from tacticalrmm.permissions import _has_perm, _has_perm_on_agent, _has_perm_on_site

from .alerting import evaluate
from .models import SnmpAlert, SnmpDevice, SnmpReading
from .provisioning import (
    NoProbeAgentError,
    ensure_probe_for_site,
    pick_probe_agent,
    probe_status,
    probe_task_exists,
)
from .serializers import (
    SnmpDeviceSerializer,
    SnmpIngestSerializer,
    SnmpProbeDeviceSerializer,
    SnmpReadingSerializer,
)

logger = logging.getLogger("trmm")

# devices are site infrastructure, so they ride on the site permissions rather than
# adding a Role field, which would mean a migration on the upstream accounts app
READ_PERM = "can_list_sites"
WRITE_PERM = "can_manage_sites"

MAX_READING_DAYS = 365

# shipped to the probe agent for discovery, so the "Erkennen" button always runs the
# same code as the scheduled poll rather than a copy that can drift
PROBE_SCRIPT = Path(__file__).resolve().parent / "probe" / "snmp_probe.py"
DISCOVER_TIMEOUT = 120


def _require(request, perm: str) -> None:
    if not _has_perm(request, perm):
        raise PermissionDenied()


def _require_site(request, site_id: int) -> None:
    if not _has_perm_on_site(request.user, site_id):
        raise PermissionDenied()


class GetAddSnmpDevices(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        _require(request, READ_PERM)

        devices = (
            SnmpDevice.objects.select_related("site__client")
            .filter_by_role(request.user)  # type: ignore
            .order_by("site__client__name", "site__name", "name")
        )

        if "site" in request.query_params:
            devices = devices.filter(site_id=request.query_params["site"])
        elif "client" in request.query_params:
            devices = devices.filter(site__client_id=request.query_params["client"])

        return Response(SnmpDeviceSerializer(devices, many=True).data)

    def post(self, request):
        _require(request, WRITE_PERM)

        serializer = SnmpDeviceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        _require_site(request, serializer.validated_data["site"].pk)
        device = serializer.save()

        data = SnmpDeviceSerializer(device).data

        # the first device at a site sets up its own poller; a failure here must
        # not break the creation, because e.g. no agent may be online yet
        if not probe_task_exists(device.site):
            try:
                ensure_probe_for_site(
                    site=device.site,
                    user=request.user,
                    api_url=request.build_absolute_uri("/"),
                )
            except NoProbeAgentError as err:
                data["probe_warning"] = str(err)
            except Exception:
                logger.exception("snmp probe provisioning failed")
                data["probe_warning"] = "probe provisioning failed, see server log"

        return Response(data)


class GetUpdateDeleteSnmpDevice(APIView):
    permission_classes = [IsAuthenticated]

    def _get(self, request, pk: int, perm: str) -> SnmpDevice:
        _require(request, perm)
        device = get_object_or_404(SnmpDevice.objects.select_related("site"), pk=pk)
        _require_site(request, device.site_id)
        return device

    def get(self, request, pk):
        return Response(
            SnmpDeviceSerializer(self._get(request, pk, READ_PERM)).data
        )

    def put(self, request, pk):
        device = self._get(request, pk, WRITE_PERM)
        serializer = SnmpDeviceSerializer(instance=device, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        # moving a device to a site the caller cannot see would be a way out of scope
        if "site" in serializer.validated_data:
            _require_site(request, serializer.validated_data["site"].pk)

        return Response(SnmpDeviceSerializer(serializer.save()).data)

    def delete(self, request, pk):
        self._get(request, pk, WRITE_PERM).delete()
        return Response("Device was removed")


class DiscoverSnmpDevice(APIView):
    """The "Erkennen" button in the device form. Walks the device from an online
    agent at its site — the same thing the discover_snmp_device MCP tool does — and
    returns what the device actually exposes, including a suggested metric_map."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        _require(request, WRITE_PERM)

        site_id = request.data.get("site")
        ip = str(request.data.get("ip") or "").strip()
        if not site_id or not ip:
            return notify_error("site and ip are required")
        _require_site(request, site_id)

        try:
            port = int(request.data.get("port") or 161)
        except (TypeError, ValueError):
            return notify_error("port must be an integer")

        community = str(request.data.get("community") or "public")
        if "•" in community and request.data.get("device"):
            # the edit form shows the community masked; an unchanged value means
            # "the stored one", which only the server still has
            device = get_object_or_404(
                SnmpDevice, pk=request.data["device"], site_id=site_id
            )
            community = device.community

        agent = pick_probe_agent(site_id)
        if agent is None:
            return notify_error("no online agent at this site to probe from")

        data = {
            "func": "runscriptfull",
            "timeout": DISCOVER_TIMEOUT,
            "script_args": ["--dump", ip, "--community", community, "--port", str(port)],
            "payload": {"code": PROBE_SCRIPT.read_text(), "shell": "python"},
            "run_as_user": False,
            "env_vars": [],
            "nushell_enable_config": settings.NUSHELL_ENABLE_CONFIG,
            "deno_default_permissions": settings.DENO_DEFAULT_PERMISSIONS,
        }
        r = asyncio.run(agent.nats_cmd(data, timeout=DISCOVER_TIMEOUT + 5, wait=True))

        # the audit record gets the masked community, same convention as the api
        audited = {
            **data,
            "script_args": [
                mask_token(a) if a == community else a for a in data["script_args"]
            ],
        }
        AuditLog.audit_test_script_run(
            username=request.user.username,
            agent=agent,
            before_value=audited,
            after_value=r,
            debug_info={"ip": request._client_ip},
        )

        if r == "timeout":
            return notify_error(f"the probe agent {agent.hostname} did not answer in time")
        if r == "natsdown":
            return notify_error("the agent cannot be reached right now")
        if not isinstance(r, dict):
            return notify_error("unexpected answer from the probe agent")
        if r.get("retcode"):
            detail = (r.get("stderr") or r.get("stdout") or "unknown error").strip()
            return notify_error(f"discovery failed on {agent.hostname}: {detail}")
        try:
            return Response(json.loads(r.get("stdout") or ""))
        except ValueError:
            return notify_error("the probe did not return json")


class SiteProbe(APIView):
    """Status and self-service setup of the site's poller.

    POST runs the provisioning again on demand - it refreshes the script body,
    repairs a broken task and re-homes a poller whose agent went away.
    """

    permission_classes = [IsAuthenticated]

    def _site(self, request, site_id: int, perm: str) -> Site:
        _require(request, perm)
        _require_site(request, site_id)
        return get_object_or_404(Site, pk=site_id)

    def get(self, request, site_id):
        site = self._site(request, site_id, READ_PERM)
        return Response(probe_status(site))

    def post(self, request, site_id):
        site = self._site(request, site_id, WRITE_PERM)
        try:
            ensure_probe_for_site(
                site=site,
                user=request.user,
                api_url=request.build_absolute_uri("/"),
            )
        except NoProbeAgentError as err:
            return notify_error(str(err))
        return Response(probe_status(site))


class SnmpDeviceReadings(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        _require(request, READ_PERM)
        device = get_object_or_404(SnmpDevice, pk=pk)
        _require_site(request, device.site_id)

        try:
            days = min(int(request.query_params.get("days", 30)), MAX_READING_DAYS)
        except ValueError:
            return notify_error("days must be an integer")

        readings = device.readings.filter(
            timestamp__gte=djangotime.now() - dt.timedelta(days=days)
        )
        if "metric" in request.query_params:
            readings = readings.filter(metric=request.query_params["metric"])

        return Response(SnmpReadingSerializer(readings, many=True).data)


class SnmpLatestReadings(APIView):
    """Newest sample per device and metric, for the fleet overview. One query for
    the whole list page instead of one round trip per device."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        _require(request, READ_PERM)
        devices = SnmpDevice.objects.filter_by_role(request.user)  # type: ignore
        if "site" in request.query_params:
            devices = devices.filter(site_id=request.query_params["site"])
        elif "client" in request.query_params:
            devices = devices.filter(site__client_id=request.query_params["client"])

        latest = (
            SnmpReading.objects.filter(device__in=devices)
            # device_id, not device: ordering by the FK would order by the related
            # model's meta ordering and break the distinct-on match
            .order_by("device_id", "metric", "-timestamp")
            .distinct("device_id", "metric")
        )

        out: dict = {}
        for reading in latest:
            out.setdefault(reading.device_id, {})[reading.metric] = {
                "value": reading.value,
                "timestamp": reading.timestamp,
            }
        return Response(out)


class SnmpOpenAlerts(APIView):
    """Open threshold alerts across the fleet, for badges in the device list."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        _require(request, READ_PERM)
        devices = SnmpDevice.objects.filter_by_role(request.user)  # type: ignore

        alerts = SnmpAlert.objects.filter(device__in=devices).select_related(
            "device__site__client"
        )
        return Response(
            [
                {
                    "device": a.device_id,
                    "device_name": a.device.name,
                    "client_name": a.device.site.client.name,
                    "site_name": a.device.site.name,
                    "metric": a.metric,
                    "severity": a.severity,
                    "created_time": a.created_time,
                }
                for a in alerts
            ]
        )


class ProbeDevices(APIView):
    """What the polling script on the probe agent asks for. Scoped to that agent's
    site, so a probe can never see or write devices at another customer."""

    permission_classes = [IsAuthenticated]

    def _site_id(self, request, agent_id: str) -> int:
        _require(request, READ_PERM)
        if not _has_perm_on_agent(request.user, agent_id):
            raise PermissionDenied()
        return get_object_or_404(Agent, agent_id=agent_id).site_id

    def get(self, request, agent_id):
        devices = SnmpDevice.objects.filter(
            site_id=self._site_id(request, agent_id), enabled=True
        )
        return Response(SnmpProbeDeviceSerializer(devices, many=True).data)

    def post(self, request, agent_id):
        site_id = self._site_id(request, agent_id)

        serializer = SnmpIngestSerializer(data=request.data, many=True)
        serializer.is_valid(raise_exception=True)

        by_id = {
            d.pk: d for d in SnmpDevice.objects.filter(site_id=site_id, enabled=True)
        }
        unknown = [r["id"] for r in serializer.validated_data if r["id"] not in by_id]
        if unknown:
            return notify_error(f"unknown or disabled device ids for this site: {unknown}")

        now = djangotime.now()
        readings, raised = [], []

        with transaction.atomic():
            for result in serializer.validated_data:
                device = by_id[result["id"]]

                if result["reachable"]:
                    device.last_seen = now
                    device.last_error = None
                    for field in ("model_name", "serial"):
                        if result.get(field):
                            setattr(device, field, result[field])
                else:
                    device.last_error = result.get("error") or "unreachable"

                device.save(
                    update_fields=["last_seen", "last_error", "model_name", "serial"]
                )

                metrics = result.get("metrics") or {}
                readings += [
                    SnmpReading(device=device, metric=metric, value=value)
                    for metric, value in metrics.items()
                ]
                raised += evaluate(device, metrics, result["reachable"])

            SnmpReading.objects.bulk_create(readings)

        return Response({
            "devices": len(serializer.validated_data),
            "readings": len(readings),
            "alerts": raised,
        })
