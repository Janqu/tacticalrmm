"""Provision a site poller with a credential bound to its assigned agent."""

import logging
from pathlib import Path

from django.db import transaction
from django.utils import timezone as djangotime

from agents.models import Agent
from autotasks.models import AutomatedTask
from autotasks.tasks import create_win_task_schedule
from clients.models import Site
from scripts.models import Script
from tacticalrmm.constants import AGENT_STATUS_ONLINE, ScriptShell, TaskType

from .models import SnmpProbeCredential, new_probe_key

logger = logging.getLogger("trmm")

# the task runs the same file the MCP discovery and the discover endpoint ship, so
# polling and discovery can never drift apart
PROBE_SCRIPT = Path(__file__).resolve().parent / "probe" / "snmp_probe.py"

SCRIPT_NAME = "QDT SNMP Poller"
SCRIPT_CATEGORY = "QDT"
TASK_NAME = "QDT SNMP Poller"

POLL_MINUTES = 5
TASK_TIMEOUT = 300


class NoProbeAgentError(Exception):
    """No online agent at the site to run the poller on."""


def pick_probe_agent(site_id: int):
    """An online agent at the site; a server makes the steadier probe."""
    return next(
        (
            a
            for a in Agent.objects.filter(site_id=site_id).order_by(
                # "server" sorts before "workstation"
                "monitoring_type"
            )
            if a.status == AGENT_STATUS_ONLINE
        ),
        None,
    )


def ensure_script() -> Script:
    """Create the poller script, or refresh its body when the shipped file changed.

    The description says edits are overwritten because they are: the file in the
    repo is the source of truth, and a hand-edited copy going stale on the server
    is exactly the drift this provisioning exists to avoid.
    """
    script = Script.objects.filter(name=SCRIPT_NAME, category=SCRIPT_CATEGORY).first()
    body = PROBE_SCRIPT.read_text()

    if script is None:
        return Script.objects.create(
            name=SCRIPT_NAME,
            shell=ScriptShell.PYTHON,
            category=SCRIPT_CATEGORY,
            script_body=body,
            default_timeout=TASK_TIMEOUT,
            description=(
                "Polls the site's SNMP devices and posts the readings back. "
                "Managed by the qdt_snmp provisioning - edits are overwritten."
            ),
        )

    if script.script_body != body or script.shell != ScriptShell.PYTHON:
        script.script_body = body
        script.shell = ScriptShell.PYTHON
        script.default_timeout = TASK_TIMEOUT
        script.save(
            update_fields=["script_body", "shell", "default_timeout", "modified_time"]
        )
    return script


def ensure_probe_credential(site, agent) -> SnmpProbeCredential:
    credential, created = SnmpProbeCredential.objects.get_or_create(
        site=site, defaults={"agent": agent}
    )
    if not created and credential.agent_id != agent.pk:
        credential.agent = agent
        credential.key = new_probe_key()
        credential.save(update_fields=["agent", "key"])
    return credential


def _task_actions(script: Script, api_url: str) -> list:
    return [
        {
            "type": "script",
            "script": script.pk,
            "name": script.name,
            "timeout": TASK_TIMEOUT,
            "script_args": [
                "--url",
                api_url,
                "--agent-id",
                "{{agent.agent_id}}",
                "--api-key",
                "{{agent.snmp_probe_key}}",
            ],
            "env_vars": [],
        }
    ]


def ensure_task(site, script: Script, api_url: str) -> AutomatedTask:
    """One poller task per site, repaired rather than duplicated when it exists."""
    agent = pick_probe_agent(site.pk)
    if agent is None:
        raise NoProbeAgentError(f"no online agent at {site.name} to run the poller on")

    actions = _task_actions(script, api_url)
    task = AutomatedTask.objects.filter(name=TASK_NAME, agent__site=site).first()

    if task is None:
        task = AutomatedTask.objects.create(
            agent=agent,
            name=TASK_NAME,
            actions=actions,
            task_type=TaskType.DAILY,
            daily_interval=1,
            run_time_date=djangotime.now(),
            task_repetition_interval=f"{POLL_MINUTES}M",
            task_repetition_duration="1D",
        )
    else:
        changed = set()
        if task.actions != actions:
            task.actions = actions
            changed.add("actions")
        if not task.enabled:
            task.enabled = True
            changed.add("enabled")
        # a poller on an agent that went away is a poller that does not run
        if task.agent_id != agent.pk and task.agent.status != AGENT_STATUS_ONLINE:
            task.agent = agent
            changed.add("agent")
        if changed:
            task.save(update_fields=[*changed, "modified_time"])

    ensure_probe_credential(site, task.agent)
    transaction.on_commit(lambda: create_win_task_schedule.delay(pk=task.pk))
    return task


def probe_task_exists(site) -> bool:
    return AutomatedTask.objects.filter(name=TASK_NAME, agent__site=site).exists()


def ensure_probe_for_site(*, site, api_url: str) -> None:
    with transaction.atomic():
        # Serialize concurrent provisioning requests for this site.
        site = Site.objects.select_for_update().get(pk=site.pk)
        ensure_task(site, ensure_script(), api_url.rstrip("/"))


def probe_status(site) -> dict:
    task = (
        AutomatedTask.objects.filter(name=TASK_NAME, agent__site=site)
        .select_related("agent")
        .first()
    )
    agent = pick_probe_agent(site.pk)
    return {
        "script": Script.objects.filter(
            name=SCRIPT_NAME, category=SCRIPT_CATEGORY
        ).exists(),
        "api_key": (
            SnmpProbeCredential.objects.filter(
                site=site, agent__site=site, agent_id=task.agent_id
            ).exists()
            if task
            else False
        ),
        "online_agent": agent.hostname if agent else None,
        "task": (
            {"enabled": task.enabled, "agent": task.agent.hostname} if task else None
        ),
    }
