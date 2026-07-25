"""Set up the polling side of a site without any hand holding.

Creating the first SNMP device at a site used to mean four manual steps: upload the
probe script, create an API key, store it as {{global.snmp_api_key}}, and build an
automated task on one of the site's agents. All four are mechanical, so they happen
here instead - once when the first device is added, and again whenever someone asks
to repair or refresh the setup.
"""

import logging
from pathlib import Path

from django.utils import timezone as djangotime
from django.utils.crypto import get_random_string

from accounts.models import APIKey, Role, User
from agents.models import Agent
from autotasks.models import AutomatedTask
from autotasks.tasks import create_win_task_schedule
from core.models import GlobalKVStore
from scripts.models import Script
from tacticalrmm.constants import AGENT_STATUS_ONLINE, ScriptShell, TaskType

logger = logging.getLogger("trmm")

# the task runs the same file the MCP discovery and the discover endpoint ship, so
# polling and discovery can never drift apart
PROBE_SCRIPT = Path(__file__).resolve().parent / "probe" / "snmp_probe.py"

SCRIPT_NAME = "QDT SNMP Poller"
SCRIPT_CATEGORY = "QDT"
TASK_NAME = "QDT SNMP Poller"
KEY_STORE_NAME = "snmp_api_key"
API_KEY_NAME = "snmp-probe"
SERVICE_USERNAME = "snmp-probe"
SERVICE_ROLE_NAME = "snmp-probe"

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


def _service_user():
    """A dedicated, login-blocked user for the probe key.

    The key only ever calls GET/POST /qdt_snmp/probe/<agent>/devices/, so it gets a
    role with exactly can_list_sites instead of inheriting the entire permission
    set of whichever admin happened to provision first. is_active must stay True
    because the API-key authenticator rejects inactive users; login is blocked by
    the unusable password and block_dashboard_login instead.
    """
    role, _ = Role.objects.get_or_create(
        name=SERVICE_ROLE_NAME, defaults={"can_list_sites": True}
    )
    if not role.can_list_sites:
        # someone reused the role name; the probe cannot work without this
        role.can_list_sites = True
        role.save(update_fields=["can_list_sites"])

    user, created = User.objects.get_or_create(
        username=SERVICE_USERNAME,
        defaults={"role": role, "block_dashboard_login": True, "email": ""},
    )
    if created:
        user.set_unusable_password()
        user.save(update_fields=["password"])
    return user


def ensure_api_key() -> None:
    """The probe authenticates with {{global.snmp_api_key}}.

    The key value never leaves the server; it is substituted into the script args
    server-side on every run. get_or_create everywhere so a concurrent first
    provision degrades to sharing the existing rows instead of failing.
    """
    if GlobalKVStore.objects.filter(name=KEY_STORE_NAME).exists():
        return

    api_key, _ = APIKey.objects.get_or_create(
        name=API_KEY_NAME,
        defaults={
            "key": get_random_string(length=32).upper(),
            "user": _service_user(),
        },
    )
    # no unique constraint on name here (upstream model), so a true race can still
    # produce a duplicate row; in practice the APIKey get_or_create above funnels
    # concurrent runs onto the same key
    GlobalKVStore.objects.get_or_create(
        name=KEY_STORE_NAME, defaults={"value": api_key.key}
    )


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
                "{{global.snmp_api_key}}",
            ],
            "env_vars": [],
        }
    ]


def ensure_task(site, script: Script, api_url: str) -> AutomatedTask:
    """One poller task per site, repaired rather than duplicated when it exists."""
    agent = pick_probe_agent(site.pk)
    if agent is None:
        raise NoProbeAgentError(
            f"no online agent at {site.name} to run the poller on"
        )

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

    create_win_task_schedule.delay(pk=task.pk)
    return task


def probe_task_exists(site) -> bool:
    return AutomatedTask.objects.filter(name=TASK_NAME, agent__site=site).exists()


def ensure_probe_for_site(*, site, api_url: str) -> None:
    ensure_api_key()
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
        "api_key": GlobalKVStore.objects.filter(name=KEY_STORE_NAME).exists(),
        "online_agent": agent.hostname if agent else None,
        "task": (
            {"enabled": task.enabled, "agent": task.agent.hostname} if task else None
        ),
    }
