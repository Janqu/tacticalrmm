"""Terminal preference contracts against Django, without messaging agents."""
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent
    from clients.models import Client, Site
    from core.models import CoreSettings
    from django.core.cache import cache
    from rest_framework.test import APIClient

    subject = "terminal-defaults-agent-001"
    fixed = datetime(2024, 1, 2, tzinfo=timezone.utc)

    def setup(platform="windows", shell="use_global", custom="", version="2.11.0", core=None, scope="all"):
        Agent.objects.all().delete()
        seed()
        Client.objects.bulk_create([Client(id=31, name="Terminal")])
        Site.objects.bulk_create([Site(id=31, name="Terminal", client_id=31)])
        Agent.objects.bulk_create([Agent(id=31, agent_id=subject, hostname="Terminal ü", site_id=31, plat=platform,
                                        default_shell=shell, default_shell_custom=custom, version=version)])
        Agent.objects.update(created_time=fixed, modified_time=fixed)
        if core == "missing":
            CoreSettings.objects.all().delete()
        else:
            CoreSettings.objects.update(default_shell_windows="powershell", default_shell_linux="bash", default_shell_darwin="bash", terminal_mode="new")
            if core:
                CoreSettings.objects.update(**core)
            CoreSettings.objects.update(created_time=fixed, modified_time=fixed)
        Role.objects.filter(pk=1).update(can_use_terminal=scope != "denied")
        role = Role.objects.get(pk=1)
        role.can_view_clients.clear()
        role.can_view_sites.clear()
        if scope == "client": role.can_view_clients.add(1)
        if scope == "site": role.can_view_sites.add(1)
        User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def state():
        return list(Agent.objects.order_by("id").values()), list(CoreSettings.objects.order_by("id").values()), snapshot()

    count = 0

    def compare(*, method="GET", uid=1, missing=False, **options):
        nonlocal count
        setup(**options)
        url = f"/agents/{'terminal-missing-agent-0001' if missing else subject}/terminal-defaults/"
        client = APIClient(raise_request_exception=False)
        client.credentials(HTTP_AUTHORIZATION="Token " + hashlib.sha256(f"contract-user-{uid}".encode()).hexdigest())
        with patch.object(Agent, "nats_cmd", new_callable=AsyncMock) as request, patch("celery.app.task.Task.apply_async") as tasks:
            result = client.generic(method, url)
            request.assert_not_called()
            tasks.assert_not_called()
        expected = result.status_code, json.loads(result.content) if result.content and result.status_code < 500 else None
        expected_state = state()
        setup(**options)
        actual = go_request(method, url, user_id=uid)
        if expected[0] >= 500:
            assert actual[0] == expected[0], (options, expected, actual)
        else:
            assert actual == expected, (method, uid, options, expected, actual)
        assert state() == expected_state, "terminal defaults read changed database state"
        count += 1

    try:
        for platform in ("windows", "linux", "darwin", "unknown"):
            for shell in ("use_global", "", "cmd", " POWERSHELL ", "bash", "custom", " custom ", "invalid"):
                compare(platform=platform, shell=shell, custom=" /usr/bin/zsh ")
            for custom in (r" C:\Tools\PwSh.EXE ", r"\\server\share\shell.exe", "C:/tool.exe", "relative", "/usr/bin/zsh", "/bad;command", "", "/bin/\"sh"):
                compare(platform=platform, shell="custom", custom=custom)
            compare(platform=platform, core="missing")
            compare(platform=platform, core={"terminal_mode": "legacy"}, method="HEAD")
        for platform in ("windows", "linux", "darwin"):
            key = "default_shell_" + platform
            for token, custom in [("custom", r" C:\Tools\PwSh.EXE "), ("custom", " /bin/zsh "), ("custom", ""), (" CMD ", ""), ("", ""), ("invalid", "")]:
                compare(platform=platform, core={key: token, key + "_custom": custom, "terminal_mode": "legacy"})
        for version in ("2.10.9", "2.11", "2.11.0rc1", "2.11.0.dev1", "2.11.0.post1", "2.11.0.post1.dev1", "2.12.0dev1", "1!1.0", "v2.11.0+local", "bad", ""):
            compare(version=version)
        for uid, scope in [(1, "all"), (2, "all"), (2, "denied"), (2, "client"), (2, "site"), (3, "all"), (4, "all"), (5, "all"), (6, "all")]:
            for method in ("GET", "HEAD"):
                for missing in (False, True):
                    compare(uid=uid, scope=scope, method=method, missing=missing)
        # Go deliberately reads fresh core values. Django caches the shell's
        # core instance while terminal_mode uses a separate fresh query.
        setup()
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + hashlib.sha256(b"contract-user-1").hexdigest())
        url = f"/agents/{subject}/terminal-defaults/"
        assert client.get(url).data["effective_default_shell"] == "powershell"
        CoreSettings.objects.update(default_shell_windows="cmd", terminal_mode="legacy")
        stale = client.get(url).data
        before = state()
        actual = go_request("GET", url)
        assert stale["effective_default_shell"] == "powershell" and stale["terminal_mode"] == "legacy"
        assert actual[0] == 200 and actual[1]["effective_default_shell"] == "cmd" and actual[1]["terminal_mode"] == "legacy"
        assert state() == before
        count += 1
        print(f"Terminal defaults contracts: {count} comparisons passed")
        return count
    finally:
        Agent.objects.all().delete()
        seed()
