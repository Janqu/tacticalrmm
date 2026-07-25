from unittest.mock import AsyncMock, patch

from asgiref.sync import async_to_sync
from django.test import SimpleTestCase

from qdt_mcp.server import (
    _api_key,
    discover_snmp_device,
    get_event_log,
    list_alerts,
    mcp_asgi_app,
    run_command,
)


async def _call_app(headers, key_valid=False):
    """Run the asgi app against an http scope, returning the messages it sent."""
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        sent.append(msg)

    scope = {"type": "http", "path": "/mcp", "method": "POST", "headers": headers}
    with patch("qdt_mcp.server._key_is_valid", AsyncMock(return_value=key_valid)):
        await mcp_asgi_app(scope, receive, send)
    return sent


def _fake_client(payload):
    """An httpx.AsyncClient stand-in that always answers with payload."""
    response = AsyncMock()
    response.status_code = 200
    response.content = b"[]"
    response.json = lambda: payload

    client = AsyncMock()
    client.request.return_value = response
    client.__aenter__.return_value = client
    return client


async def _with_key(coro_fn, client, key="TESTKEY"):
    token = _api_key.set(key)
    try:
        with patch("qdt_mcp.server.httpx.AsyncClient", return_value=client):
            return await coro_fn()
    finally:
        _api_key.reset(token)


async def _run_command_with_key(key, client):
    await _with_key(
        lambda: run_command(agent_id="abc", command="whoami", shell="powershell"),
        client,
        key,
    )


class TestMCPAuth(SimpleTestCase):
    def test_missing_api_key_is_rejected(self):
        """An anonymous client must not reach the mcp app and enumerate the tools."""
        for headers in ([], [(b"x-api-key", b"")]):
            with self.subTest(headers=headers):
                sent = async_to_sync(_call_app)(headers)
                self.assertEqual(sent[0]["status"], 401)

    def test_unknown_api_key_is_rejected_before_the_handshake(self):
        """Presence of the header is not enough: an unknown key must not list tools."""
        sent = async_to_sync(_call_app)(
            [(b"x-api-key", b"NOT-A-REAL-KEY")], key_valid=False
        )
        self.assertEqual(sent[0]["status"], 401)

    def test_valid_api_key_reaches_the_mcp_app(self):
        """A key the backend accepts must be let through, with the key bound for tools."""
        reached = {}

        async def fake_app(scope, receive, send):
            reached["key"] = _api_key.get()

        with patch("qdt_mcp.server._app", fake_app):
            async_to_sync(_call_app)([(b"x-api-key", b"GOOD-KEY")], key_valid=True)

        self.assertEqual(reached["key"], "GOOD-KEY")

    def test_api_key_is_forwarded_verbatim(self):
        """Tools must pass the caller's key through so trmm applies their permissions."""
        client = _fake_client({})
        async_to_sync(_run_command_with_key)("SECRETKEY123", client)

        kwargs = client.request.call_args.kwargs
        self.assertEqual(kwargs["headers"]["X-API-KEY"], "SECRETKEY123")
        self.assertEqual(
            kwargs["json"],
            {
                "cmd": "whoami",
                "shell": "powershell",
                "timeout": 30,
                "run_as_user": False,
            },
        )


class TestDiscoverTemplateGuard(SimpleTestCase):
    """The discover args go through TestScript's server-side {{...}} expansion, so
    a community of {{global.snmp_api_key}} would send the probe key to a chosen
    host. Template syntax is therefore rejected before anything runs."""

    def test_template_syntax_is_rejected(self):
        base = {"agent_id": "abc", "ip": "10.0.0.1"}
        for override in (
            {"ip": "{{global.snmp_api_key}}"},
            {"community": "{{agent.hostname}}"},
        ):
            with self.subTest(**override):
                with self.assertRaises(RuntimeError):
                    async_to_sync(discover_snmp_device)(**{**base, **override})


class TestAlertQuery(SimpleTestCase):
    """/alerts/ only applies its resolved and snoozed filters when the value is false,
    so sending true would silently return everything instead of narrowing."""

    def _body(self, **kwargs):
        client = _fake_client([])
        async_to_sync(_with_key)(lambda: list_alerts(**kwargs), client)
        return client.request.call_args.kwargs["json"]

    def test_defaults_to_open_alerts_only(self):
        self.assertEqual(
            self._body(days=7),
            {"timeFilter": 7, "resolvedFilter": False, "snoozedFilter": False},
        )

    def test_include_resolved_omits_the_filters(self):
        self.assertEqual(self._body(include_resolved=True), {"timeFilter": 30})

    def test_severity_and_client_are_passed_as_lists(self):
        body = self._body(severity=["error"], client_id=3)
        self.assertEqual(body["severityFilter"], ["error"])
        self.assertEqual(body["clientFilter"], [3])


class TestEventLogOrdering(SimpleTestCase):
    """Truncating to `limit` must keep the newest entries, whichever branch runs."""

    def _messages(self, log, **kwargs):
        client = _fake_client(log)
        result = async_to_sync(_with_key)(
            lambda: get_event_log(agent_id="abc", limit=2, **kwargs), client
        )
        return [e["message"] for e in result]

    def test_sorts_descending_when_entries_carry_a_timestamp(self):
        log = [
            {"time": "2026-07-25T01:00:00Z", "message": "older"},
            {"time": "2026-07-25T09:00:00Z", "message": "newer"},
            {"time": "2026-07-24T09:00:00Z", "message": "oldest"},
        ]
        self.assertEqual(self._messages(log), ["newer", "older"])

    def test_takes_the_tail_when_there_is_no_timestamp(self):
        log = [
            {"eventType": "error", "message": "oldest"},
            {"eventType": "error", "message": "middle"},
            {"eventType": "error", "message": "newest"},
        ]
        self.assertEqual(self._messages(log), ["newest", "middle"])

    def test_filters_by_event_type_before_truncating(self):
        log = [
            {"eventType": "information", "message": "noise"},
            {"eventType": "error", "message": "real"},
        ]
        self.assertEqual(self._messages(log, event_type="error"), ["real"])
