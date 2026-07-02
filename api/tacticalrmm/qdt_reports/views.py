import datetime as dt

from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from alerts.models import Alert
from clients.models import Client
from tacticalrmm.constants import AgentMonType
from tacticalrmm.permissions import _has_perm_on_client

PATCH_LOOKBACK_DAYS = 30


def _agent_patch_summary(agent: Agent) -> dict:
    updates = agent.winupdates.all()
    since = djangotime.now() - dt.timedelta(days=PATCH_LOOKBACK_DAYS)
    return {
        "installed": updates.filter(installed=True).count(),
        "installed_recently": updates.filter(
            installed=True, date_installed__gte=since
        ).count(),
        "pending": updates.filter(installed=False, action="approve").count(),
        "missing": updates.filter(
            installed=False, action__in=["nothing", "inherit"]
        ).count(),
    }


def _agent_check_summary(agent: Agent) -> dict:
    checks = agent.get_checks_with_policies(exclude_overridden=True)
    summary = {"passing": 0, "failing": 0, "pending": 0}
    for check in checks:
        result = getattr(check, "check_result", None)
        status = result.status if result else "pending"
        summary[status] = summary.get(status, 0) + 1
    return summary


class ClientHealthReportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, client_id: int):
        client = get_object_or_404(Client, pk=client_id)

        if not _has_perm_on_client(request.user, client.pk):
            from rest_framework.exceptions import PermissionDenied

            raise PermissionDenied()

        agents = (
            Agent.objects.filter(site__client=client)
            .select_related("site")
            .order_by("hostname")
        )

        open_alerts = (
            Alert.objects.filter(agent__site__client=client, resolved=False)
            .select_related("agent")
            .order_by("-alert_time")
        )

        agent_rows = []
        totals = {
            "online": 0,
            "offline": 0,
            "overdue": 0,
            "patches_pending": 0,
            "patches_installed_recently": 0,
            "checks_failing": 0,
        }

        for agent in agents:
            status = agent.status
            totals[status] = totals.get(status, 0) + 1

            patches = _agent_patch_summary(agent)
            checks = _agent_check_summary(agent)
            totals["patches_pending"] += patches["pending"]
            totals["patches_installed_recently"] += patches["installed_recently"]
            totals["checks_failing"] += checks["failing"]

            agent_rows.append(
                {
                    "hostname": agent.hostname,
                    "site": agent.site.name,
                    "status": status,
                    "monitoring_type": agent.monitoring_type,
                    "operating_system": agent.operating_system,
                    "last_seen": agent.last_seen,
                    "needs_reboot": agent.needs_reboot,
                    "patches": patches,
                    "checks": checks,
                    "open_alerts": open_alerts.filter(agent=agent).count(),
                }
            )

        alert_rows = [
            {
                "hostname": alert.agent.hostname if alert.agent else None,
                "severity": alert.severity,
                "message": alert.message,
                "alert_time": alert.alert_time,
            }
            for alert in open_alerts[:50]
        ]

        return Response(
            {
                "client": {"id": client.pk, "name": client.name},
                "generated_at": djangotime.now(),
                "patch_lookback_days": PATCH_LOOKBACK_DAYS,
                "summary": {
                    "total_agents": len(agent_rows),
                    "servers": sum(
                        1
                        for a in agents
                        if a.monitoring_type == AgentMonType.SERVER
                    ),
                    "workstations": sum(
                        1
                        for a in agents
                        if a.monitoring_type == AgentMonType.WORKSTATION
                    ),
                    "online": totals["online"],
                    "offline": totals["offline"],
                    "overdue": totals["overdue"],
                    "patches_pending": totals["patches_pending"],
                    "patches_installed_recently": totals[
                        "patches_installed_recently"
                    ],
                    "checks_failing": totals["checks_failing"],
                    "open_alerts": open_alerts.count(),
                },
                "agents": agent_rows,
                "alerts": alert_rows,
            }
        )
