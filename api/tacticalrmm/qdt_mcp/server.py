"""MCP server exposing device analysis and control to AI assistants.

Mounted into the ASGI app at /mcp (see tacticalrmm/asgi.py). Every tool forwards the
caller's X-API-KEY to TRMM's own REST API instead of touching the ORM, so role
permissions, agent scoping, AgentHistory and AuditLog all apply unchanged.

Tools must stay async: the ASGI process is a single worker that also serves every
dashboard websocket, so a blocking call would freeze the UI for its whole duration.
"""

import contextvars
from typing import Any

import httpx
from django.conf import settings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

from tacticalrmm.util_settings import get_backend_url

API_URL = get_backend_url(
    settings.ALLOWED_HOSTS[0], settings.TRMM_PROTO, settings.TRMM_BACKEND_PORT
)
# self-signed certs are normal on docker and dev installs
VERIFY_SSL = getattr(settings, "MCP_VERIFY_SSL", True)
# must stay <= the proxy_read_timeout on nginx's /mcp location
API_TIMEOUT = 300.0

_api_key: contextvars.ContextVar[str] = contextvars.ContextVar("trmm_api_key")

READ = ToolAnnotations(readOnlyHint=True, openWorldHint=True)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=True)

# Must be passed explicitly. Left unset, the sdk auto-enables dns rebinding protection
# for its default host of 127.0.0.1 and then rejects every request that reaches us
# through nginx with a 421, because the Host header is the api domain.
_HOSTS = [h for h in settings.ALLOWED_HOSTS if h != "*"]
TRANSPORT_SECURITY = TransportSecuritySettings(
    enable_dns_rebinding_protection="*" not in settings.ALLOWED_HOSTS,
    allowed_hosts=_HOSTS + [f"{h}:*" for h in _HOSTS],
    allowed_origins=[f"{settings.TRMM_PROTO}://{h}" for h in _HOSTS]
    + [f"{settings.TRMM_PROTO}://{h}:*" for h in _HOSTS],
)

mcp = FastMCP(
    "tacticalrmm",
    instructions=(
        "Analyze and manage devices in Tactical RMM. Identify a device with "
        "list_agents first, then use its agent_id with the other tools. Read the "
        "device state before changing it, and note that shell/script syntax depends "
        "on the agent's 'plat' field (windows, linux or darwin)."
    ),
    stateless_http=True,
    json_response=True,
    transport_security=TRANSPORT_SECURITY,
)


async def _api(method: str, path: str, **kwargs: Any) -> Any:
    async with httpx.AsyncClient(
        base_url=API_URL, verify=VERIFY_SSL, timeout=API_TIMEOUT
    ) as client:
        r = await client.request(
            method, path, headers={"X-API-KEY": _api_key.get()}, **kwargs
        )

    if r.status_code >= 400:
        # TRMM's notify_error puts the human readable reason in the body
        raise RuntimeError(f"{method} {path} failed [{r.status_code}]: {r.text[:500]}")

    return r.json() if r.content else {"ok": True}


def _pick(obj: dict, *fields: str) -> dict:
    return {f: obj.get(f) for f in fields}


# ---------------------------------------------------------------- read only


@mcp.tool(annotations=READ)
async def list_clients() -> list[dict]:
    """List clients and their sites, with agent counts and failing check counts.

    Use this to turn a company or location name into the client_id / site_id that
    list_agents and list_alerts take.
    """
    clients = await _api("GET", "/clients/")
    return [
        _pick(c, "id", "name", "agent_count", "failing_checks", "maintenance_mode")
        | {
            "sites": [
                _pick(s, "id", "name", "agent_count", "failing_checks")
                for s in c.get("sites") or []
            ]
        }
        for c in clients
    ]


@mcp.tool(annotations=READ)
async def list_alerts(
    days: int = 30,
    severity: list[str] | None = None,
    client_id: int | None = None,
    include_resolved: bool = False,
    limit: int = 50,
) -> list[dict]:
    """List alerts newest first, by default only unresolved and unsnoozed ones.

    The quickest way to find out what is currently broken, across the whole fleet or
    for one client. severity entries are "info", "warning" or "error".
    """
    # this endpoint is queried with PATCH, not GET. Its resolved/snoozed filters only
    # take effect when the value is false, so passing true would silently return
    # everything rather than only resolved alerts.
    body: dict[str, Any] = {"timeFilter": days}
    if not include_resolved:
        body["resolvedFilter"] = False
        body["snoozedFilter"] = False
    if severity:
        body["severityFilter"] = severity
    if client_id is not None:
        body["clientFilter"] = [client_id]

    alerts = await _api("PATCH", "/alerts/", json=body)
    alerts.sort(key=lambda a: a.get("alert_time") or "", reverse=True)
    return [
        _pick(
            a,
            "id",
            "alert_time",
            "severity",
            "alert_type",
            "message",
            "hostname",
            "agent_id",
            "client",
            "site",
            "resolved",
            "snoozed",
        )
        for a in alerts[:limit]
    ]


@mcp.tool(annotations=READ)
async def list_agents(
    client_id: int | None = None,
    site_id: int | None = None,
    monitoring_type: str | None = None,
    search: str | None = None,
) -> list[dict]:
    """List managed devices with a summary of each.

    monitoring_type is "server" or "workstation". search matches a substring of the
    hostname, case insensitively. Returns agent_id, which every other tool needs.
    """
    params: dict[str, Any] = {}
    if site_id is not None:
        params["site"] = site_id
    elif client_id is not None:
        params["client"] = client_id
    if monitoring_type:
        params["monitoring_type"] = monitoring_type

    agents = await _api("GET", "/agents/", params=params)

    if search:
        needle = search.lower()
        agents = [a for a in agents if needle in (a.get("hostname") or "").lower()]

    return [
        _pick(
            a,
            "agent_id",
            "hostname",
            "client_name",
            "site_name",
            "status",
            "plat",
            "operating_system",
            "last_seen",
            "needs_reboot",
            "monitoring_type",
            "maintenance_mode",
        )
        for a in agents
    ]


@mcp.tool(annotations=READ)
async def get_agent(agent_id: str) -> dict:
    """Get hardware, OS and network detail for one device."""
    a = await _api("GET", f"/agents/{agent_id}/")
    return _pick(
        a,
        "agent_id",
        "hostname",
        "client",
        "site_name",
        "status",
        "plat",
        "goarch",
        "operating_system",
        "version",
        "description",
        "last_seen",
        "boot_time",
        "public_ip",
        "local_ips",
        "cpu_model",
        "total_ram",
        "disks",
        "physical_disks",
        "graphics",
        "make_model",
        "logged_in_username",
        "last_logged_in_user",
        "needs_reboot",
        "maintenance_mode",
        "monitoring_type",
        "time_zone",
        "effective_default_shell",
        "patches_last_installed",
    )


@mcp.tool(annotations=READ)
async def ping_agent(agent_id: str) -> dict:
    """Check whether a device is currently reachable. Cheap; use before long commands."""
    return await _api("GET", f"/agents/{agent_id}/ping/")


@mcp.tool(annotations=READ)
async def list_processes(agent_id: str, limit: int = 25) -> list[dict]:
    """List running processes on a device, heaviest CPU consumers first."""
    procs = await _api("GET", f"/agents/{agent_id}/processes/")
    procs.sort(
        key=lambda p: (
            float(p.get("cpu_percent") or 0),
            float(p.get("membytes") or 0),
        ),
        reverse=True,
    )
    return procs[:limit]


@mcp.tool(annotations=READ)
async def list_services(
    agent_id: str,
    status: str | None = None,
    search: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """List Windows services on a device with their current state.

    A Windows server has several hundred services, so filter rather than listing them
    all. status is "running" or "stopped"; search matches the service or display name.
    """
    services = await _api("GET", f"/services/{agent_id}/")

    if status:
        services = [
            s for s in services if (s.get("status") or "").lower() == status.lower()
        ]
    if search:
        needle = search.lower()
        services = [
            s
            for s in services
            if needle in (s.get("name") or "").lower()
            or needle in (s.get("display_name") or "").lower()
        ]

    return [
        # binpath and description are long and rarely decide anything
        _pick(s, "name", "display_name", "status", "start_type", "pid", "username")
        for s in services[:limit]
    ]


@mcp.tool(annotations=READ)
async def list_checks(agent_id: str) -> list[dict]:
    """List the monitoring checks on a device and whether they currently pass."""
    checks = await _api("GET", f"/agents/{agent_id}/checks/")
    return [
        # the outcome lives on the nested check_result, not on the check itself
        _pick(c, "id", "readable_desc", "check_type")
        | _pick(
            c.get("check_result") or {},
            "status",
            "alert_severity",
            "last_run",
            "fail_count",
            "more_info",
        )
        for c in checks
    ]


@mcp.tool(annotations=READ)
async def get_event_log(
    agent_id: str,
    log_type: str = "Application",
    days: int = 1,
    event_type: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """Read a Windows event log from a device, newest entries first.

    log_type is "Application", "System" or "Security". event_type filters on "error",
    "warning" or "information", and is usually what you want. Keep days small; the
    Security log is huge and can take minutes to collect.
    """
    log = await _api("GET", f"/agents/{agent_id}/eventlog/{log_type}/{days}/")

    if event_type:
        log = [
            e
            for e in log
            if (e.get("eventType") or "").lower() == event_type.lower()
        ]

    # ponytail: the entry shape comes from the agent binary, which lives in another
    # repo, so detect the timestamp field instead of hardcoding one. Without it, assume
    # the log is appended chronologically and take the tail.
    stamp = next(
        (k for k in ("time", "timeGenerated", "timeWritten") if log and k in log[0]),
        None,
    )
    if stamp:
        log.sort(key=lambda e: e.get(stamp) or "", reverse=True)
        return log[:limit]

    return log[-limit:][::-1]


@mcp.tool(annotations=READ)
async def list_software(agent_id: str) -> Any:
    """List software installed on a device."""
    return await _api("GET", f"/software/{agent_id}/")


@mcp.tool(annotations=READ)
async def list_windows_updates(agent_id: str) -> Any:
    """List Windows updates known for a device, including pending ones."""
    return await _api("GET", f"/winupdate/{agent_id}/")


@mcp.tool(annotations=READ)
async def list_pending_actions(agent_id: str) -> Any:
    """List actions queued for a device that have not completed yet."""
    return await _api("GET", f"/agents/{agent_id}/pendingactions/")


@mcp.tool(annotations=READ)
async def get_agent_history(agent_id: str, limit: int = 25) -> list[dict]:
    """Show recent commands and scripts run on a device, newest first.

    Useful for finding out what has already been tried before acting.
    """
    history = await _api("GET", f"/agents/{agent_id}/history/")
    # the endpoint has no ordering; time is iso-8601 utc so it sorts lexically
    history.sort(key=lambda h: h.get("time") or "", reverse=True)
    return [
        _pick(h, "time", "type", "username", "command", "script_name", "results")
        for h in history[:limit]
    ]


@mcp.tool(annotations=READ)
async def list_scripts(search: str | None = None) -> list[dict]:
    """List saved scripts available to run. Returns the id that run_script needs.

    search matches a substring of the name or description, case insensitively.
    """
    scripts = await _api("GET", "/scripts/")
    picked = [
        _pick(
            s,
            "id",
            "name",
            "description",
            "shell",
            "supported_platforms",
            "args",
            "default_timeout",
            "syntax",
        )
        for s in scripts
    ]

    if search:
        needle = search.lower()
        picked = [
            s
            for s in picked
            if needle in (s.get("name") or "").lower()
            or needle in (s.get("description") or "").lower()
        ]

    return picked


# ----------------------------------------------------------------- mutating


@mcp.tool(annotations=WRITE)
async def run_command(
    agent_id: str,
    command: str,
    shell: str,
    timeout: int = 30,
    run_as_user: bool = False,
) -> Any:
    """Run a shell command on a device and return its output.

    shell must match the platform: "powershell" or "cmd" on Windows, "bash" on Linux
    and macOS. Check the agent's "plat" field first. timeout is in seconds.
    """
    return await _api(
        "POST",
        f"/agents/{agent_id}/cmd/",
        json={
            "cmd": command,
            "shell": shell,
            "timeout": timeout,
            "run_as_user": run_as_user,
        },
    )


@mcp.tool(annotations=WRITE)
async def run_script(
    agent_id: str,
    script_id: int,
    args: list[str] | None = None,
    env_vars: list[str] | None = None,
    timeout: int = 30,
    run_as_user: bool = False,
) -> Any:
    """Run a saved script on a device and wait for the result.

    Get script_id from list_scripts. env_vars entries are "KEY=VALUE" strings.
    Returns stdout, stderr, retcode and execution_time.
    """
    return await _api(
        "POST",
        f"/agents/{agent_id}/runscript/",
        json={
            "script": script_id,
            "output": "wait",
            "args": args or [],
            "env_vars": env_vars or [],
            "timeout": timeout,
            "run_as_user": run_as_user,
        },
    )


@mcp.tool(annotations=WRITE)
async def run_script_code(
    agent_id: str,
    code: str,
    shell: str = "powershell",
    args: list[str] | None = None,
    env_vars: list[str] | None = None,
    timeout: int = 60,
    run_as_user: bool = False,
) -> Any:
    """Run ad-hoc script code on a device without saving it as a script.

    Prefer this over run_command whenever the logic needs more than one line. shell is
    "powershell", "cmd", "python", "shell" (posix sh), "nushell" or "deno" — note these
    names differ from run_command's, which uses "bash" rather than "shell".
    Returns stdout, stderr, retcode and execution_time.
    """
    return await _api(
        "POST",
        f"/scripts/{agent_id}/test/",
        json={
            "code": code,
            "shell": shell,
            "args": args or [],
            "env_vars": env_vars or [],
            "timeout": timeout,
            "run_as_user": run_as_user,
        },
    )


@mcp.tool(annotations=WRITE)
async def kill_process(agent_id: str, pid: int) -> Any:
    """Terminate a process on a device by its pid."""
    return await _api("DELETE", f"/agents/{agent_id}/processes/{pid}/")


@mcp.tool(annotations=WRITE)
async def control_service(agent_id: str, service_name: str, action: str) -> Any:
    """Start, stop or restart a Windows service on a device.

    action is "start", "stop" or "restart". service_name is the short name from
    list_services, not the display name.
    """
    return await _api(
        "POST",
        f"/services/{agent_id}/{service_name}/",
        json={"sv_action": action},
    )


@mcp.tool(annotations=WRITE)
async def run_checks(agent_id: str) -> Any:
    """Force all monitoring checks on a device to run now."""
    return await _api("POST", f"/checks/{agent_id}/run/")


@mcp.tool(annotations=WRITE)
async def reboot_agent(agent_id: str) -> Any:
    """Reboot a device immediately. Confirm with the user before calling this."""
    return await _api("POST", f"/agents/{agent_id}/reboot/")


# ------------------------------------------------------------------- prompts


@mcp.prompt(title="Triage a device")
def triage_device(hostname: str) -> str:
    """First pass over a device that is reported as misbehaving."""
    return (
        f"Triage the device '{hostname}' in Tactical RMM and report what is wrong.\n\n"
        "Work in this order, and stop early once you have a clear cause:\n"
        "1. list_agents to resolve the hostname to an agent_id, then ping_agent. If it "
        "is offline, say so and stop: nothing below will reach it.\n"
        "2. get_agent for OS, uptime, disk space and pending reboot. Note the 'plat' "
        "field, it decides which shell any command has to use.\n"
        "3. list_alerts and list_checks for what is already flagged.\n"
        "4. get_event_log with event_type='error' over the last day, first Application "
        "then System.\n"
        "5. list_processes, and list_services if a service looks involved.\n"
        "6. get_agent_history to see what has already been tried.\n\n"
        "Then report the most likely cause, the evidence for it, and a concrete "
        "suggested fix. Do not run commands, restart services, kill processes or "
        "reboot anything without asking first."
    )


@mcp.prompt(title="Fleet health summary")
def fleet_health(client_name: str = "") -> str:
    """What needs attention right now, across the fleet or one client."""
    scope = f" for the client '{client_name}'" if client_name else " across all clients"
    return (
        f"Summarise what needs attention{scope} in Tactical RMM.\n\n"
        + (
            "Start with list_clients to resolve the name to a client_id.\n"
            if client_name
            else ""
        )
        + "Use list_alerts for unresolved alerts, then list_agents to spot devices "
        "that are offline, overdue or pending a reboot.\n\n"
        "Group the findings by how urgent they are, name the affected hostnames, and "
        "point out anything that looks like one underlying cause hitting several "
        "devices. Read only: do not change anything."
    )


# ------------------------------------------------------------------- plumbing

_app = mcp.streamable_http_app()


async def mcp_asgi_app(scope, receive, send) -> None:
    """The MCP app, gated on X-API-KEY and with the key bound for the tools to forward.

    Rejecting before the app runs matters: without it an anonymous client completes the
    MCP handshake and can enumerate every tool.
    """
    if scope["type"] == "http":
        key = dict(scope.get("headers") or []).get(b"x-api-key", b"").decode()
        if not key:
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8")],
                }
            )
            await send(
                {"type": "http.response.body", "body": b"missing X-API-KEY header"}
            )
            return

        token = _api_key.set(key)
        try:
            await _app(scope, receive, send)
        finally:
            _api_key.reset(token)
        return

    # lifespan: starts the streamable http session manager's task group, without which
    # every tool call fails with "Task group is not initialized"
    await _app(scope, receive, send)
