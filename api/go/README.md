# Go backend port

Work in progress: this module is **not yet a replacement for Django**.
The target is the complete backend, including HTTP, WebSockets, background jobs,
SSO, reporting, SNMP, inventory, Matrix, push notifications and MCP.

The implementation uses Fiber v3, GORM and PostgreSQL. Versions are pinned in
`go.mod` / `go.sum`. The existing NATS Go module remains separate.

## Implemented

Existing Knox tokens and `X-API-KEY` credentials, token expiration/renewal,
active-user checks, role permissions and these method/path combinations:

| Method | Path |
| --- | --- |
| GET | `/` |
| GET | `/core/version/` |
| GET, PUT | `/core/settings/` |
| GET, POST | `/core/urlaction/` |
| PUT, DELETE | `/core/urlaction/<int:pk>/` |
| GET, POST | `/core/keystore/` |
| PUT, DELETE | `/core/keystore/<int:pk>/` |
| GET, DELETE | `/core/codesign/` |
| GET, POST | `/clients/` |
| GET, PUT, DELETE | `/clients/<int:pk>/` |
| GET, POST | `/clients/sites/` |
| GET, PUT, DELETE | `/clients/sites/<int:pk>/` |
| GET, PATCH, POST | `/core/customfields/` |
| GET, PUT, DELETE | `/core/customfields/<int:pk>/` |
| POST | `/v2/checkcreds/` |
| POST | `/v2/login/` |
| POST | `/logout/` |
| POST | `/logoutall/` |
| GET, POST | `/accounts/users/` |
| GET, PUT, DELETE | `/accounts/<int:pk>/users/` |
| GET, DELETE | `/accounts/users/<int:pk>/sessions/` |
| DELETE | `/accounts/sessions/<str:pk>/` |
| GET, POST | `/accounts/roles/` |
| GET, PUT, DELETE | `/accounts/roles/<int:pk>/` |
| GET, POST | `/accounts/apikeys/` |
| PUT, DELETE | `/accounts/apikeys/<int:pk>/` |
| PATCH | `/accounts/users/ui/` |
| PUT | `/accounts/resetpw/` |
| PUT | `/accounts/reset2fa/` |
| POST | `/accounts/users/setup_totp/` |
| POST, PUT | `/accounts/users/reset/` |
| POST, PUT | `/accounts/users/reset_totp/` |
| GET, HEAD | `/agents/` |
| GET, HEAD | `/agents/history/`, `/agents/<agent_id>/history/` |
| GET, HEAD | `/agents/v2/history/`, `/agents/v2/<agent_id>/history/` |
| GET, HEAD | `/agents/notes/`, `/agents/notes/<int:pk>/`, `/agents/<agent_id>/notes/` |
| GET, HEAD, POST | `/scripts/` |
| GET, HEAD, PUT, DELETE | `/scripts/<int:pk>/` |
| GET, HEAD, POST | `/scripts/snippets/` |
| GET, HEAD, PUT, DELETE | `/scripts/snippets/<int:pk>/` |
| GET, HEAD | `/automation/policies/`, `/automation/policies/<int:pk>/` |
| GET, HEAD | `/automation/policies/overview/`, `/automation/policies/<int:pk>/related/` |
| GET, HEAD | `/alerts/templates/`, `/alerts/templates/<int:pk>/`, `/alerts/templates/<int:pk>/related/` |
| GET, HEAD, PUT, DELETE | `/alerts/<int:pk>/` |
| POST | `/alerts/bulk/` |
| PATCH | `/alerts/` |
| GET, HEAD | `/checks/`, `/checks/<int:pk>/`, `/automation/policies/<int:policy>/checks/` |
| PATCH | `/checks/<int:pk>/history/` |
| GET, HEAD | `/automation/checks/<int:check>/status/` |
| GET, HEAD | `/tasks/`, `/tasks/<int:pk>/`, `/automation/policies/<int:policy>/tasks/` |
| GET, HEAD | `/automation/tasks/<int:task>/status/`, `/automation/tasks/<int:task>/run/` |
| GET, HEAD | `/agents/<agent_id>/checks/`, `/agents/<agent_id>/tasks/` |
| POST | `/automation/patchpolicy/`, `/automation/patchpolicy/reset/` |
| PUT, DELETE | `/automation/patchpolicy/<int:pk>/` |
| PATCH | `/logs/audit/`, `/logs/debug/` |
| GET, HEAD | `/software/`, `/software/<agent_id>/` |
| GET | `/software/chocos/` |
| GET, HEAD | `/winupdate/<agent_id>/` |
| PUT | `/winupdate/<int:pk>/`, `/winupdate/bulk/` |
| POST | `/winupdate/<agent_id>/scan/` |
| POST | `/winupdate/<agent_id>/install/` |
| POST (remote, `output="wait"`) | `/agents/<agent_id>/runscript/` |
| POST (agent token) | `/api/v3/winupdates/`, `/api/v3/superseded/` |
| GET, HEAD | `/logs/pendingactions/`, `/agents/<agent_id>/pendingactions/` |
| DELETE | `/logs/pendingactions/<int:pk>/` (scheduled reboots require NATS) |
| GET | `/agents/<agent_id>/ping/` (requires NATS) |
| POST | `/checks/<agent_id>/run/` (requires NATS) |
| POST | `/agents/<agent_id>/wmi/` (requires NATS) |
| GET, HEAD | `/agents/<agent_id>/processes/`, `/services/<agent_id>/`, `/services/<agent_id>/<svcname>/` (requires NATS) |
| DELETE | `/agents/<agent_id>/processes/<int:pid>/` (requires NATS) |
| POST, PUT | `/services/<agent_id>/<svcname>/` (requires NATS) |
| POST | `/agents/<agent_id>/reboot/`, `/agents/<agent_id>/shutdown/` (requires NATS) |
| PATCH | `/agents/<agent_id>/reboot/` (scheduled reboot, requires NATS) |
| POST, PUT | `/software/<agent_id>/` (Chocolatey install / inventory refresh; requires NATS) |
| GET | `/agents/<agent_id>/eventlog/<logtype>/<days>/`, `/agents/<agent_id>/registry/` (requires NATS) |
| POST | `/agents/<agent_id>/registry/create-key/`, `rename-key/`, `create-value/`, `rename-value/`, `modify-value/` (requires NATS) |
| DELETE | `/agents/<agent_id>/registry/delete-key/`, `delete-value/` (requires NATS) |
| GET | `/agents/versions/` |
| GET, HEAD | `/agents/<agent_id>/terminal-defaults/`, `/agents/scripthistory/` |
| PATCH | `/api/v4/<agentid>/<pk>/chocoresult/` (DRF agent token) |
| POST | `/agents/<agent_id>/cmd/` (requires NATS) |
| PATCH | `/api/v3/<pk>/<agentid>/histresult/` (plain command/script results; DRF agent token) |
| POST | `/agents/notes/` |
| PUT, DELETE | `/agents/notes/<int:pk>/` |

The account and client/site GET routes also serve HEAD, with Django's existing permission behavior.
Unimplemented routes currently return 404. No Python proxy or placeholder
success responses are used. SSO login and OPTIONS metadata are still pending.
CommonMiddleware redirects, full response-header parity and deployment-specific
settings overrides also need to be ported before cutover.

API-key mutations include Django-compatible validation and secret-free audit
projections. Each mutation and its audit entry share a transaction. UI updates
use an explicit field allowlist. Password resets use Django 4.2's default
PBKDF2-SHA256 format with 600,000 iterations; Django verifies generated hashes
in the differential tests. Existing Knox tokens remain valid, as in Django.
TOTP provisioning matches PyOTP's URI format and serializes concurrent setup
requests so only one request creates a secret.

Both administrative reset aliases use POST for password resets and PUT for
TOTP resets, matching Django's shared `UserActions` view. Users may reset their
own credentials without account-management permission. Other targets require
`can_manage_accounts`; the global local-logon block denies both cases. Configure
`ROOT_USER` to match Django's setting: other administrators cannot reset that
account, while the root user may reset itself. These routes follow Django's
`LocalUserPerms`, including its distinct behavior for SSO targets. They preserve
existing Knox tokens and update the audit metadata without logging credentials.

Role creation validates all declared permission flags, unique names and existing
client/site IDs. The role, relationship rows and Django-compatible creation audit
commit together. Unknown/read-only input is ignored, duplicate IDs collapse, and
failed writes roll back. Role creation does not dispatch a MeshCentral task in
Django. Role updates/deletions now commit their database changes, audit entries
and a durable MeshCentral request together. Updates preserve omitted flags/scopes;
deletions clear affected users' role IDs without changing their audit timestamps.
As in Django, scope-only edits do not appear in the role audit because its save
hook runs before many-to-many updates. Go authorization reads roles directly;
shared Django permission-cache invalidation in mixed deployments is not ported.

User creation follows Django's distinct create-view behavior: NFKC username
normalization, lowercasing the email domain, secure password hashing and the
existing UI defaults. First/last names retain whitespace on creation; integer
role IDs are applied while string role IDs are ignored. Supplied superuser/staff,
installer and other undeclared flags cannot grant privileges. PUT user updates
are partial and use the serializer field allowlist, including nullable roles,
login timestamps and normalized IP addresses. They preserve existing passwords,
TOTP secrets and Knox tokens. Account-management permission is always required;
root protection allows self-editing, matching the regular Django configuration.
User data, the creation/modification audits and Mesh requests commit together.

User listing includes literal case-insensitive search and social-account display
metadata for database-configured OIDC applications. Settings-backed social apps
and sites-framework overrides remain pending. Deletion reproduces Django-owned
dependent-row cascades and nullable ownership links, retaining unrelated records
and database sessions. Deletion, its audit and Mesh request commit atomically.

Agent reads (`agents_reads.go`, `agents_wmi.go`,
`agents_cache.go`) reproduce `AgentPerms`/`AgentNotesPerms`/`AgentHistoryPerms`,
`_has_perm_on_agent` and `filter_by_role`, including Django's quirks: HEAD is
checked as an edit/management request (`HEAD /agents/` is 403 or, as in Django,
a 500 from a missing `agent_id` kwarg) and unknown agents are 404 for scoped
users. The table serializer's WMI-derived fields are ported from `Agent`
properties. `checks` comes from Django's Redis cache (pickled dict, decoded by a
strict allow-list reader); set `DJANGO_CACHE_REDIS_URL` to the cache database
(Django uses db 10), otherwise detailed `GET /agents/` fails with 500 instead
of returning wrong data. Cache misses return Django's zero summary. Django
leaves these querysets unordered; Go orders by id. `tools/compare_agents_reads.py`
is wired into `compare_django.py`.

Agent note writes preserve management permissions, agent scope, nullable/blank
notes, partial updates, writable agent/user relationships and read-only timestamps.
Creation uses the authenticated author; Django has no audit or task hooks for
notes. Updates/deletions lock the note until the transaction commits. Deliberate
safety differences: reassignment also requires access to the destination agent
(Django checks only the source), and missing/invalid creation agent IDs return
400 instead of an unhandled exception. The agent-specific notes alias remains
read-only in Go; Django's POST alias raises a handler argument error.
`tools/compare_agents_reads.py` compares write responses and stored note data,
including denied requests and preservation of unrelated audit/user records.

Client/site reads include role scoping, custom fields, nested sites and the
Django-specific agent counts and maintenance annotations. Detail authorization
and HEAD permissions preserve the existing differences between clients and sites.
Custom-field arrays use ID order; Django defines no ordering for these rows, so
the comparison checks their content independently of database query-plan order.

Client/site writes and custom-field CRUD run in one transaction with their audit
rows (Django dispatches no MeshCentral task for them). Permissions, DRF validation
messages, Django's exact response strings (including the literal `{client} was
updated`), role-scope auto-grant on creation, `?move_to_site` agent moves and the
model collector's cascades (custom values, deployments, SNMP devices, reports,
role/policy/alert-template scope rows, SET_NULL history/task links; PROTECT/RESTRICT
rows fail with 500) are compared against Django in `tools/compare_client_writes.py`.
Deliberate differences: multi-step failures (invalid initial site, invalid custom-field
entry) roll back everything instead of leaving Django's partial client/site or its
add+delete audit pair; missing `client`/`site` keys and non-numeric `move_to_site`
return 400/404 instead of Django's unhandled 500. Refused with 501 (no writes):
changing a client/site policy or alert template or moving a site to another client
(Django dispatches Celery `cache_agents_alert_template` and clears Django-cache keys)
and client creation with `initialsetup` (CoreSettings.save side effects).

The standalone `cmd/mesh-sync` command now implements the MeshCentral permission
reconciliation: eligible users, superuser overrides, client/site scopes, account
creation/deletion, device rights and display names. It reads the existing Django
tables through GORM and authenticates using MeshCentral's AES-GCM token format.
The same command also runs as a worker for durable requests from user creation/
updates/deletions and role updates/deletions. Other synchronization triggers
remain pending.

Login primitives now verify Django's default PBKDF2-SHA256, PBKDF2-SHA1,
Argon2id/Argon2i (version 19), bcrypt-SHA256 and scrypt password encodings.
They report required password upgrades after successful verification, perform
dummy hashing for unknown/unusable passwords and pad failed legacy PBKDF2 checks.
TOTP verification matches PyOTP 2.9's normalization and the existing ±10-step
window. `/v2/checkcreds/` issues a three-minute Knox token when TOTP needs setup;
`/v2/login/` verifies TOTP and issues a five-hour token. Login respects inactive,
dashboard-blocked, SSO and locally blocked accounts, upgrades old password hashes,
records audit events and last-login data, and creates Django-readable database
sessions with CSRF cookies. Same-user sessions are retained; anonymous sessions
rotate and different-user/password sessions are flushed. Existing session expiry
values and browser-close sessions are preserved. Login writes are transactional:
failed auditing/session/token persistence does not leave a partial login.

Redis minute/day throttles default to 10/300 per IP for each route, with independent
scopes and DRF-style `429`/`Retry-After`. Authenticated Token/API-key requests bypass
anonymous throttling, matching Django. Atomic Redis updates prevent concurrent
requests from exceeding the limit. Cache failures reject anonymous logins with 503.
Go throttle keys use a separate namespace from Django's serialized cache; a mixed
Django/Go deployment therefore does **not** share a single login attempt budget.
Malformed hashes fail closed. Resource limits reject PBKDF2 above 10 million
iterations, bcrypt cost above 16, Argon2 above 256 MiB/10 passes/32 lanes and
scrypt above 256 MiB or its bounded work parameters. Custom hashes beyond these
limits and Argon2 version 16 require explicit compatibility work before cutover.
Empty TOTP secrets always fail rather than accepting an OTP derived from no key.

Write endpoints currently accept JSON. Other parsers and exact malformed-JSON
diagnostics are pending. Missing or non-string/non-null reset passwords return
400 instead of reproducing Django's unhandled exception. Failed mutations roll
back their audit entries; failed auditing rolls back the mutation. These error
and concurrency behaviors are deliberate safety improvements, not parity claims.
User creation similarly rejects missing fields, invalid input types, null names,
null characters and oversized fields with 400 rather than reproducing unhandled
exceptions. A missing role or duplicate username leaves no account or audit
behind. Unusual IDNA mapping differences between Python and Go and custom Django
username/email validators require further compatibility work before cutover.
Missing login usernames/TOTP fields also return 400 instead of Django's unhandled
key lookup errors; empty TOTP secrets cannot authenticate.
Reset actions similarly return structured 400 responses for missing or invalid
IDs/passwords rather than reproducing unhandled lookup/type errors.

Core settings, URL actions and the key store follow Django's permission classes
(HEAD needs the edit permission, as in DRF), partial-serializer validation
(including nested list-item errors), token masking and audit rules. Django audits
CoreSettings and key-store values with plaintext secrets; Go writes `"[redacted]"`
for tokens, SMTP/Twilio/Mesh secrets and key-store values (changes are still
detected on the real values). Settings PUT commits the update, audit and a Mesh
outbox request together. PUT refuses with 501, without changing anything, when it
would enable SSO (needs the code-sign service) or change the default
workstation/server policy or alert template (needs Celery agent re-caching and
Django cache purges). Not yet handled: Django's `core_settings` Redis cache entry
is not purged (up to 10 minutes stale for Django workers), HOSTED/DEMO overrides,
a missing settings row (Go returns 404), 403/405 responses for unsupported
methods on these paths, and the `all_timezones` list, which is generated from the
development host's `zoneinfo` (`internal/httpapi/core_timezones.go`).
Compare with `tools/compare_core.py` (run from `compare_django.py`).

## Run

Use Go 1.25 or newer and a **development copy** of the existing Django database:

```sh
export DATABASE_URL='postgresql://user:password@localhost:5432/trmm_dev?sslmode=disable'
export CORS_ALLOWED_ORIGINS='https://rmm.example.com'
# To enable login, use the SAME signing secret and cookie domain as Django:
export DJANGO_SECRET_KEY='your-development-django-secret'
export SESSION_COOKIE_DOMAIN='example.com'
export ROOT_USER='your-existing-root-username'
export REDIS_URL='redis://127.0.0.1:6379/0'
# Apply the explicit Go-owned outbox migration before using user or role mutations:
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/001_mesh_sync.sql
# Required only before enabling the Go note_async mode:
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/002_script_note_completion.sql
go run ./cmd/api
```

The default address is `127.0.0.1:8080`; override it with `LISTEN_ADDR`.
Database and table names are mapped explicitly. Startup does not create or
change the schema. The migrations add Go-owned outbox and note-completion tables; they do not alter
Django columns. The completion table references existing histories and notes. Credentials, SQL parameters and request bodies are not logged.
The first `CORS_ALLOWED_ORIGINS` entry supplies the TOTP issuer hostname, matching
Django's first frontend origin. New TOTP setup requires that origin to be set.
Without both `DJANGO_SECRET_KEY` and `REDIS_URL`, login returns 503; configuring
only one fails startup. Session cookies are Secure/HttpOnly/SameSite=Lax, matching
the repository settings. HTTPS termination and an ingress that replaces untrusted
`X-Forwarded-For` headers are required. Login audit IPs currently cover the direct
peer and first forwarded address; other IpWare header precedence is pending.
`LOGIN_THROTTLE_PREFIX` defaults to `trmm:go:throttle:` and must match across Go
workers. The four Django `TRMM_{CHECK_CREDS,LOGIN}_{MIN,DAY}_THROTTLE` environment
variables accept positive counts up to 10,000. Custom Django cookie settings,
`SECRET_KEY_FALLBACKS`, authentication backends, and DEBUG/DEMO TOTP bypasses are
not implemented; verify deployment overrides before cutover.

### MeshCentral synchronization

```sh
# DATABASE_URL points at the existing development database.
export MESH_WS_URL='wss://mesh.example.com'
go run ./cmd/mesh-sync --dry-run
go run ./cmd/mesh-sync
# Run alongside the API to process requests automatically:
go run ./cmd/mesh-sync --worker
# Or process at most one ready generation, suitable for an external scheduler:
go run ./cmd/mesh-sync --worker --once
```

`MESH_WS_URL` is the base URL, without `/control.ashx` or an authentication query;
it defaults to `ws://127.0.0.1:4430`. External MeshCentral deployments and custom
ports must set it explicitly. Credentials and the company name come from
`core_coresettings`. `TRMM_DISABLE_MESH_SYNC_TASK=true` skips the command entirely
and leaves durable requests pending.
In contrast, the database setting `sync_mesh_with_trmm=false` removes all
TRMM-managed MeshCentral accounts, matching Django. Managed accounts use Django's
existing `___<digits>` recognition rule; other accounts are preserved.

Dry runs query MeshCentral and print a deterministic plan without passwords or
authentication tokens. A PostgreSQL advisory lock prevents simultaneous Go runs;
it does **not** coordinate with Django's Redis lock. Run only one implementation's
synchronizer against a deployment. The database snapshot transaction ends before
network mutations. Each WebSocket request has a 120-second deadline and
each reconciliation a two-hour deadline; cancellation closes active connections.

The worker checks for pending requests every five seconds, then processes further
pending changes immediately after a successful run. One persistent row coalesces
requests using increasing generation numbers. It acknowledges only the generation
read before the run, preserving changes committed during synchronization. Failures
retain the request and schedule a retry after 30 seconds; a new mutation makes it
ready immediately. Delivery is at least once, so a crash after remote writes can
repeat reconciliation. No database transaction remains open during remote writes.
There is no separate broker or generic job framework. Deployment supervision and
the remaining Celery tasks/schedules are still pending.

To inspect progress:

```sql
SELECT generation, completed_generation, attempts, requested_at, next_attempt_at
FROM go_mesh_sync;
```

Equal generation counters mean the latest request completed. The absence of a row
means no request has been queued. A stopped worker leaves API changes committed
and their requests pending. If enqueueing fails, the user/role mutation and its audit
roll back together.

Compared with Python's fire-and-forget writes, Go requires mutation acknowledgments
and returns a failing exit status on errors. The request/response handling follows
[MeshCentral's server implementation](https://github.com/Ylianst/MeshCentral/blob/master/meshuser.js),
including the users response without a response ID. Earlier successful remote
changes cannot be rolled back; another run reconciles the current state. Existing
unlinked accounts are reused instead of being created twice. Invalid/duplicate
agent node IDs, malformed inventories and paginated node responses abort before
any mutation. Paging support remains pending. The source's chunk thresholds and
seven-second pauses are retained, once per chunk of changed devices.

## Checks

```sh
go test -race ./...
go vet ./...
python3 -m unittest discover -s tools -p 'test_*.py'
python3 tools/inventory.py --check
```

`internal/accounts/testdata/auth_vectors.json` contains 46 deterministic password
and TOTP cases generated by Django 4.2.30 and PyOTP 2.9.0. Go tests consume these
independent reference results; CI also regenerates and compares them using
`python tools/auth_vectors.py --check` (requires `argon2-cffi` and `bcrypt`).

`contracts/inventory.json` records Python source hashes, route declarations and
settings gates, handlers, model classes, tasks, schedules and MCP tools.
It includes local QDT extensions. It is a **static declaration inventory**, not
a resolved API schema or a claim that any listed feature is implemented.
Refresh it after reviewing Python changes with `python3 tools/inventory.py`.

The differential test builds tables from the actual Django models in a unique
PostgreSQL schema, seeds identical data for both implementations, then compares
status codes, JSON bodies, authentication challenges, token/API-key/user changes
and audit records. It verifies password hashes and provisioning URIs with Django
and PyOTP, and exercises transaction rollback and concurrent key/TOTP creation.
Login comparisons also verify issued token digests/lifetimes, cookie attributes,
session signatures in both directions, session rotation, password upgrades,
audits, per-minute/day throttles, cache failures and concurrent login limits.
Account-action cases cover self/administrator permissions, root protection and
local-logon blocking. Role cases compare every permission flag, scoped
relationships, duplicate names and the complete audit projection against Django.
It removes its schema afterward. It accepts only an explicitly supplied loopback
database whose name ends in `_test`.

```sh
docker run --detach --rm --name tacticalrmm-go-test \
  --publish 127.0.0.1:55439:5432 \
  --env POSTGRES_PASSWORD=trmm-test-only --env POSTGRES_DB=trmm_go_test postgres:16-alpine
docker run --detach --rm --name tacticalrmm-go-redis-test \
  --publish 127.0.0.1:56379:6379 redis:7-alpine
go build -o /tmp/tacticalrmm-go-api ./cmd/api
go build -o /tmp/tacticalrmm-go-mesh-sync ./cmd/mesh-sync
../tacticalrmm/.venv/bin/python tools/compare_django.py \
  --dsn postgresql://postgres:trmm-test-only@127.0.0.1:55439/trmm_go_test \
  --go-binary /tmp/tacticalrmm-go-api \
  --mesh-binary /tmp/tacticalrmm-go-mesh-sync
docker stop tacticalrmm-go-test
docker stop tacticalrmm-go-redis-test
```

This requires the existing Django requirements and their native libraries. On
Apple Silicon macOS with Homebrew, set `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`
when running the reference test so WeasyPrint finds Pango/GObject.

With `--mesh-binary`, the same isolated Django schema also feeds a simulated
MeshCentral WebSocket server. The comparison executes the real Python task and
compares its mutations and resulting state with the Go command, including dry
runs and repeat execution. Python independently decrypts Go authentication tokens.
Failure checks cover invalid node IDs, rejected mutations and concurrent-run locks.
Go tests additionally cover missing/paginated inventories and cancellation.
Worker checks exercise API-to-Mesh dispatch, persisted retry delays, process
crash recovery, request coalescing, changes during synchronization, continuous
polling and graceful shutdown. User creation, renaming, deactivation and deletion are
verified through the API, outbox and simulated MeshCentral server. Account tests
also check Unicode normalization, email/IP validation, privilege-field rejection,
root protection, transaction rollback and concurrent username uniqueness.
Listing cases cover search escaping, social metadata and read permissions.
Deletion cases compare dependent records and injected rollback failures.
Client/site cases compare scoped responses, custom fields, counts and HEAD rules.
Role comparisons cover the complete mutation/audit
state and whether Django dispatches a task; injected outbox failures must roll
back the role, scope, user and audit changes.
These checks do not replace validation against a deployed MeshCentral version.

## Manager read migration

Script-library reads include hidden/community filters, separate list/detail fields
and nullable arrays. Automation Manager reads include policy definitions,
inheritance-based agent counts, patch settings and scoped assignments/overview.
Alerts Manager reads include template settings, relations and alert details.
All use the caller's existing authentication and Django's GET/HEAD permission
rules. Their differential tests run from `tools/compare_django.py` in CI. For
a focused local iteration, pass `--manager-reads-only` to the same harness; it
retains the isolated-schema and read-side-effect checks. The added coverage
contains 124 script, 112 automation and 340 alert comparisons. Lists for models
without Django ordering are compared as sets of records; ordered client/site
relations and array contents retain their exact ordering checks.

This stage does not migrate policy/check/task mutations, scheduled execution,
alert delivery or the MCP transport. Production remains on Django until the
remaining side effects and cutover checks have passed.

## Script and alert writes

Script-library creation, editing and deletion preserve serializer validation,
community-script protections, audit projections and dependent-row cleanup.
Policy-linked edits invalidate the existing Redis cache namespace. Database
changes and audits are atomic; cache failure rolls back the edit. Audit values
use Django's default 512 KiB limit; custom AUDIT_MAX_VALUE_BYTES overrides remain
pending. Snippets support listing, detail, creation, editing and deletion, with
separate read and management permissions and no audit hooks (matching Django).

Existing alerts support editing, deletion and bulk resolve/snooze actions.
Matrix delivery rows and nullable SNMP links are handled transactionally.
These operations do not create alerts or send notifications. Deliberate safety
differences: reassignment also checks destination-agent permissions; malformed
bulk/snooze requests return 400 and missing deletes return 404 instead of Django's
unhandled 500. Late database failures roll back all dependent changes.

Run `tools/compare_django.py --write-flows-only` with the same local test database
arguments for the focused write checks: 82 script, 99 snippet and 93 alert
comparisons, including deliberate safety differences and rollback checks. The
default suite includes these checks.

## Monitoring reads

Check list/detail and policy-check lists include descriptions, assigned tasks,
direct alert-template settings and Django's empty result placeholders. Check
history uses PATCH with a CheckResult ID, matching Django; its descending time
order is preserved. Task list/detail and policy-task lists include schedule
descriptions, check names and direct alert-template settings. Automation check
and task status endpoints return stored result rows and hostnames. The task
`/run/` GET/HEAD alias reads status only; execution via POST remains unimplemented.

PATCH `/alerts/` supplies dashboard counts/top alerts and client, severity,
time, resolved and snoozed filters. Detail and query responses share one alert
serializer. Invalid or overflowing query inputs return explicit 400 responses
where Django may raise an unhandled exception.

Permissions follow Django, including management permissions for HEAD. Policy
status endpoints retain Django's automation-permission check without additional
client/site filtering; ordinary check/task lists and alert queries are scoped.
Agent-specific aliases also resolve inherited policies, as described below.

Run `tools/compare_django.py --monitoring-reads-only` with the local test database
arguments for 196 check, 280 task and 357 alert-query comparisons; the default
regression suite includes them. Unordered model lists are compared by content;
dashboard alert ordering and descending history ordering remain exact checks.

## Agent monitoring inheritance

Agent check/task reads combine direct entries with active agent, site, client
and default policies. They honor inheritance blocks, agent/site/client exclusions,
platform support and duplicate policy assignments. Enforced checks take priority;
inherited checks retain Django's type-group order. Results belong only to the
requested agent. Existing serializers are shared with the global/detail views.

Go deliberately recomputes from the database instead of loading Django's cached
Python model objects. Policy edits are therefore visible immediately; Python cache
entries remain untouched. Direct check override flags are reset/recomputed and
serialized in one transaction, with a lock on the agent and rollback on failure.
Unlike Django's first cold-cache response, the returned flags reflect that same
recomputation. Both GET and HEAD enforce agent scope; Django omits the HEAD check.

Use `tools/compare_django.py --agent-monitoring-only` for 73 inheritance,
result isolation, permission, freshness and rollback comparisons. This suite is
also part of the default regression run. These reads do not execute checks/tasks
or dispatch background jobs.

## Patch policy administration and logs

Automation patch policies support creation, partial editing and deletion, with
the existing Django defaults, validation and audit projections. Mutations and
audits commit together. Source and destination agents are both checked against
the caller's scope. Missing creation policy IDs and ownerless updates return 400
instead of Django's unhandled exceptions.

Bulk reset uses the existing client/site precedence and role scope. Only the eight
inheritance fields are reset; other patch settings and audit timestamps remain
unchanged. A missing/ambiguous agent policy or late database error rolls back the
whole reset, including audits. Malformed client/site selectors return 400.

Audit and debug log queries include scoped filters, nested site data, JSON values
and UTC timestamps. Audit paging preserves Django's page clamping and uses an
explicit sort-field allowlist. Debug queries retain the 1000-row limit. Audit
scope preserves Django's client-over-site precedence when both are restricted;
debug scope combines them. Invalid query inputs return 400. Configured timezone
validity is checked, although Django's ReadOnlyField timestamps do not use it.

`tools/compare_django.py --patch-logs-only` runs 47 CRUD/rollback, 112 bulk-reset
and 461 log-query checks. The default suite includes these checks. The shared
signed-integer validator also accepts negative numeric strings and integral
decimals; `--core-only` runs the existing core regression checks independently.
These operations do not install updates, execute agents or send notifications.

## Software, updates and pending actions

Software reads expose the stored global/per-agent inventory and latest Chocolatey
catalog. Missing or duplicate per-agent inventory rows retain Django's empty-list
response. Catalog access requires authentication and does not use software role
permissions; HEAD returns 405. Global inventory HEAD safely returns a scoped
response where Django's permission code raises a missing-argument exception.

Windows update reads format installation dates in the configured default timezone.
Single edits use the serializer field allowlist and check both current and new
agent ownership. Bulk approvals affect only accessible updates. These database
changes do not trigger update scans or installations and create no audit rows,
matching the plain Django model.

Pending-action reads include computed descriptions, due dates and expiry of
scheduled reboots in the agent/default timezone, including DST transitions.
Expiry and serialization are transactional; invalid records roll back the whole
request. Agent scope is also enforced for HEAD. Non-scheduled cancellations are
atomic and do not dispatch jobs. Scheduled reboot cancellation requires configured
NATS; without it, it returns 501 before any expiry or deletion.
Denied cancellation requests likewise cannot alter an expired reboot's status.

`tools/compare_django.py --endpoint-management-only` runs 142 software, 85 update
and 168 pending-action checks. The default suite includes these checks.

## Agent commands

Set `NATS_URL` to an explicit `nats://host:4222` or `tls://host:4222` endpoint.
Credentials belong in `NATS_USER` (default `tacticalrmm`) and `NATS_PASSWORD`
(defaults to `DJANGO_SECRET_KEY`), not in the URL. TLS certificate verification
remains enabled. Without configuration, command endpoints return 501.

Ping sends up to three requests. Single-agent check execution and scheduled reboot
cancellation send exactly one request, with no automatic retry after an ambiguous
timeout. Authorization and agent scope are checked before publication. Cancellation
deletes the locked pending row only after an `ok` acknowledgment. A subsequent DB
failure preserves the row but cannot undo the remote cancellation.

Transport uses the existing MessagePack protocol, bounded connection/request
deadlines and decoded reply sizes. The 1 MiB reply check happens after NATS receives
the message; configure the broker's `max_payload` to bound transport allocations.
Non-finite numbers, invalid UTF-8 and MessagePack extensions are rejected before
JSON serialization. No responder is treated as a timeout; invalid cancellation
replies return 502 without deleting the row. Invalid ping replies report offline.
`--agent-commands-only --nats-url nats://127.0.0.1:54222` runs isolated broker-backed
contracts with simulated agents. The test harness rejects non-loopback brokers and
does not inherit NATS configuration from the shell. CI runs this suite separately
from contracts that verify the unconfigured transport.

Process listing and termination enforce process-management permissions and agent
scope. PIDs must fit a nonnegative MessagePack uint64; oversized values return 400
before publication. Process lists must contain objects; malformed replies return
502. Termination is never retried. WMI refresh requires agent-edit permission and
accepts only `ok`; it triggers the agent's existing `sysinfo` flow.

Service list reads cache the reply in `agents_agent.services`; detail reads do not
change it. GET and HEAD preserve Django's command dispatch and cache behavior.
Names are URL-decoded before publication. For compatibility, service detail reads
still return the string `natsdown` with status 200, whereas list reads return 400.
Service actions support `start`, `stop` and `restart`; startup changes support
`auto`, `autodelay`, `manual` and `disabled`. Invalid inputs are rejected before
publication. Restart sends start only after a successful stop acknowledgment;
neither step is retried. A failed start cannot undo a successful stop. These
operations do not update the cached service list; refresh it to observe the result.
POSIX agents reject service actions, matching Django.

Service POST requests have a 75-second context deadline for both 32-second NATS
requests and connection setup. Other endpoints retain their 30-second context
deadline except the reads described below; the HTTP write ceiling is 200 seconds. Deployment proxies must permit
these longer requests. A proxy/client timeout cannot undo an issued agent command.

Power commands require reboot permission and agent scope. Immediate reboot and
shutdown each send one request and accept only `ok`. Scheduled reboots validate
the local date in the agent's timezone (core timezone when unset), including
Python-compatible DST fold/gap behavior. The scheduler expiration is five minutes
after the requested local wall time. Linux/macOS scheduling remains unsupported,
matching Django. Invalid dates and year overflow are rejected before publication.

Only an acknowledged schedule creates a pending action. A DB insert failure after
acknowledgment cannot undo the remote task; no automatic retry or compensation is
attempted. Power commands are tested only against simulated agents on a local broker.

The isolated broker suite covers 1,828 command/process/service/power/software/diagnostic
and raw-command/history-callback contracts. The
endpoint-management suite adds twenty-seven checks that all command routes fail with 501
without changing agent rows when NATS is not configured.

Software refresh retrieves the agent inventory and atomically updates its first
stored inventory row, or creates one if absent. Existing duplicate rows are kept
for Django compatibility. The short post-reply transaction serializes Go refreshes;
legacy Django callbacks can still create duplicates during a mixed deployment.

Chocolatey installation commits its pending action before dispatch so immediate
agent callbacks can find it. A positive acknowledgment retains it. Unlike Django,
ambiguous transport failures and malformed replies retain the pending action;
an explicit negative acknowledgment removes it only while still pending. A completed
callback is never discarded by this cleanup. Commands are never retried. No audit
or command-history rows are added, matching the source. Linux/macOS are rejected.
Software removal remains unported; installation completion uses the callback below.
Use `--software-writes-only --nats-url nats://127.0.0.1:54222` for the 108 focused
software contracts, including committed-row visibility before acknowledgment and
completed-callback preservation during failed dispatch.

Event-log reads preserve the log name and day count sent to the agent. `Security`
uses a 180-second agent timeout and 182-second NATS timeout; other logs use 30/32
seconds. HTTP context budgets are 195 and 40 seconds respectively. The existing
1 MiB decoded reply limit still applies, so large logs need a smaller day range.

Registry browsing requires agent version 2.10.0 or newer using PEP 440 comparison
against that boundary, with no platform restriction added beyond the source.
Path normalization, paging defaults and response fields match Django. It uses a
30-second NATS timeout within a 40-second HTTP context. Invalid versions return
400, unavailable transport returns 400, and malformed/structured-error replies
return 502 instead of Django's unhandled errors. HEAD returns 405 after permission
checks on both read endpoints.
Use `--diagnostic-reads-only --nats-url nats://127.0.0.1:54222` for the 74 event-log
and 106 registry-browse comparisons.

Registry writes use the same version, permission and agent-scope checks. Key and
value creation, deletion and renaming, plus value modification, preserve the
source payload and response fields. Paths are trimmed, type names uppercased,
and value names preserved. Invalid field types return 400 before dispatch.
Key renaming uses a 60-second NATS timeout and 70-second HTTP budget; other writes
use 30/40 seconds. Unknown or malformed replies cannot produce a success response.
No command is retried and no local database rows are changed. A lost response
cannot establish whether the remote registry change was applied.
Use `--registry-writes-only --nats-url nats://127.0.0.1:54222` for the 425 registry
write contracts. Read and write fixtures use separate agent subjects so they can
run concurrently against the isolated broker.

Agent version metadata returns the configured `LATEST_AGENT_VER` (default `2.11.0`,
matching Django settings) and role-scoped hostnames. Set the environment value to
match any Django local-settings override; this endpoint does not check for releases.
Terminal defaults resolve agent overrides against global shell settings, validate
custom executable paths and report support for the new terminal from version 2.11.0.
Go reads current global settings instead of reproducing Django's 600-second shell cache.

Script history filters script name and paired date ranges, optionally limiting the
newest rows. Unlike the unscoped Django source, Go applies customer/site scope before
the limit. Invalid limits and dates return 400 rather than an unhandled server error.
No remote commands run and no database rows change through these metadata endpoints.
Use `--agent-metadata-only` for 31 version, 138 terminal-default and 50 script-history
contracts. The default CI comparison includes these three flows.

The Chocolatey result callback authenticates against `authtoken_token`, separate
from dashboard Knox tokens and API keys. The token's active user must be linked to
the URL agent, and the pending action must belong to that agent and be a Chocolatey
installation. Mismatches and ID zero return 404. Results update only `output`,
`installed` and completion status under a row lock, preserving other details.
The source's output-text success heuristic is retained; invalid results/details
are rejected without changing the row. This is the first ported agent callback,
not the full v3/v4 API.
`--agent-callbacks-only` runs 57 authentication, ownership, result and rollback
contracts; the default CI suite includes them.

See [MIGRATION_NEXT.md](MIGRATION_NEXT.md) for the dependency-ordered execution,
publish, update and scheduler workstreams. These later slices remain pending.

Single-agent raw commands support a validated 1–180 second execution timeout,
with a 190-second HTTP budget. Their history row commits before the NATS request
so early callbacks can update it. Delivery is never retried; history remains on
timeout or other ambiguous failures. Successful replies create the source-compatible
command audit with a JSON string value and the existing audit-size limit.

The v3 history callback supports plain `cmd_run` histories (`results`) and plain
`script_run` histories (`results` and `script_results`), including deleted script
relations. It binds the URL and history row to the agent token, locks the row,
and rejects attempted reassignment. Task, combined collector/note and legacy note histories without Go completion
markers return 501 before mutation.
Script collectors use the stored history field association and require a string
`script_results.stdout`. Field value and history are committed atomically;
failed validation or either database write rolls back both. Repeated callbacks
reapply the value without adding another value row, matching Django. A replay
can therefore overwrite a later manual field edit; this is not a no-op guarantee. JSON result shapes and large integers are preserved.
The API's 4 MiB request limit returns 413 without mutation; Django's larger-body
truncation behavior is not enabled. All 54 script-callback comparisons passed.
`--collector-callbacks-only` adds 156 contracts covering all field targets/types,
replay, concurrent callbacks and rollback of both history and field writes.

`--raw-commands-only --nats-url nats://127.0.0.1:54222` runs 82 locally verified
contracts, including a real callback from the simulated NATS agent before its
command acknowledgment. The shared audit change also passed all 158 core
contracts, `go test -race ./...` and `go vet ./...`. No production execution or
deployment was performed.

### Publish transport and the first scheduled job

Pure script snippet, argument and environment transformations are implemented
with injected resolvers, preserving tested Python quoting and replacement
behavior. `python tools/compare_script_expansion.py` runs 394 comparisons against
the actual Python source functions plus 17 explicit unsupported-case checks.
Python-only regex constructs, ambiguous unordered objects and unsupported value
types are rejected. A read-only database resolver now supports explicitly listed
Agent/Site/Client scalar fields, their supported relations, all six custom-field
types/defaults, and exact global-key lookups. Its 181 isolated DB cases check
values and unchanged database state. It requires an already authorized root;
arbitrary properties, methods, model objects and unsupported fields are rejected.
Missing or duplicate global keys return typed errors without DebugLog writes.
Full property lookup remains pending. The synchronous execution route uses this
explicitly supported resolver subset and rejects unsupported forms before dispatch.

`agentbus.Client.Publish` sends once and waits for the broker's flush response.
Its timeout covers connection, send and flush. `PublishError.Ambiguous` marks
failures after sending may have begun; callers must retain execution state and
must not automatically resend. A successful flush does not establish agent
execution, including when there is no subscriber. Fake-peer failure tests and
an opt-in local-broker test cover this behavior; existing Request tests remain
enabled.

`cmd/scheduled-jobs` provides one bounded, DB-only job:

```sh
go build -o /tmp/tacticalrmm-go-jobs ./cmd/scheduled-jobs
# DATABASE_URL and LATEST_AGENT_VER must be explicitly configured.
/tmp/tacticalrmm-go-jobs --job resolve-pending-actions --dry-run
# Optional NATS_URL/NATS_USER/NATS_PASSWORD for scan publication:
/tmp/tacticalrmm-go-jobs --job auto-approve-win-updates --dry-run
```

Without `--dry-run`, `resolve-pending-actions` completes pending `agentupdate`
rows only when the agent's normalized PEP 440 version equals the configured
latest version and its source-compatible status is online. It reports selected,
eligible and updated counts. The transaction locks the relevant actions and
agents, aborts atomically on invalid versions or database errors, and prevents
concurrent Go job runs with an advisory lock. `--now` supplies a fixed RFC3339
clock for reproducible checks. No remote commands, notifications or other
pending-action types are processed.

The pending-actions CLI has a 35-second overall budget and the job a 30-second
budget; lock waits are limited to five seconds. All 22 isolated Django
comparisons passed.

`auto-approve-win-updates` mirrors the Celery auto-approve task: it prunes and
approves each agent under separate commits (approval failures skipped), then
publishes `getwinupdates` to online agents at version >= 1.3.0 in chunks of 40.
`TRMM_DISABLE_APPROVE_UPDATES_TASK` disables the job. `--scan-pause` and
`TRMM_WINUPDATE_APPROVE_SCAN_PAUSE_MS` control the inter-chunk delay. An invalid
version on an online agent aborts the scan phase after approvals have committed.
All 12 focused comparisons passed via
`--winupdate-auto-approve-only --jobs-binary ... --nats-url ...`.

No timer is installed for either job: disable and drain only Django's
corresponding producer before scheduling Go, and stop Go before restoring
Django on rollback. Other Celery jobs remain unchanged. Scheduled Windows
update installation remains pending.

### Windows update scan, install and result ingestion

The scan route requires Windows-update permission and agent scope. It commits
superseded-update cleanup before publishing `getwinupdates`, allowing an
immediate authenticated callback. Cleanup and scan ingestion share an agent
lock, but Django writers do not participate in that lock. A known pre-send
failure returns 503; an ambiguous publication returns 502 without a retry.
Broker acceptance is not scan completion. With NATS disabled, the route returns
501 before cleanup.

POST `/winupdate/<agent_id>/install/` reuses the same permission, scope and
publish budget. It commits superseded cleanup, effective-policy auto-approval
and approved GUID selection before publishing `installwinupdates`. Null GUIDs
and duplicates are preserved. POSIX agents are rejected with 400 before any
mutation; Django's install view omits that guard. Known pre-send failures return
503 after the committed prune/approve; ambiguous publication returns 502 without
retry. Manual install does not set `patches_last_installed`.

The agent-token POST callback validates the complete scan before mutations,
updates the highest-ID existing GUID, creates eligible new updates, removes
stale uninstalled rows and prunes superseded versions in one transaction.
Installed rows are preserved by stale cleanup. Source-specific duplicate,
missing-KB and NULL-GUID behavior is covered. Strict scalar validation and
atomic rollback intentionally replace source partial writes on malformed data.
The superseded callback deletes matching GUID rows only for its bound agent.

Cleanup shares a PEP 440 parser with the pending-update job. The Django name
`LooseVersion` actually aliases `packaging.version.Version`. All 26 cleanup
comparisons and 128 scan/install/callback comparisons passed locally, including
the publish-to-callback flow. Focused flags are `--winupdate-supersedence-only`
and `--winupdate-execution-only --nats-url nats://127.0.0.1:54222`.

Effective policy and approval helpers are now implemented: fresh inherited
policies, agent overrides, transactional default creation with the appropriate
audit context, exact severity-based approval and approved GUID selection.
All 42 differential cases passed. Scheduled approval is available as the
`auto-approve-win-updates` one-shot job; scheduled install remains on Celery.

PATCH `/api/v3/winupdates/` now records per-GUID installation results, bound
to the authenticated agent. Success updates flags and the installation timestamp;
failure changes only the result. Supersedence cleanup is atomic with the update.
Strict boolean validation and missing-GUID 404 responses are deliberate safety
differences; repeated success refreshes the timestamp as in Django.
`--winupdate-results-only` verifies 34 contracts including rollback.
PUT `/api/v3/winupdates/` supports completion only when the effective policy
does not request a reboot. It atomically updates `needs_reboot` and prunes
superseded updates; reboot-required cases return 501 and roll back all writes.
`--winupdate-completion-only` covers 36 contracts. Reboot completion remains
blocked until the agent protocol carries a stable execution identity.
Mixed deployments must keep reboot-required completion on Django. Nothing
in this tranche changes production routing or schedules.

### Stored scripts

POST `/agents/<agent_id>/runscript/` supports remote `output="wait"`, `output="forget"`, `output="note"` and `output="collector"` with
`can_run_scripts` and agent scope. It expands snippets, request arguments and
environment values, honors the stored run-as-user override, and atomically
commits audit/history before its one NATS dispatch. Callbacks can therefore arrive
before the response. Missing-value diagnostics honor the freshly read debug
level. Unsupported lookup syntax/modes fail before writes or sending; failures
after dispatch retain the execution records and never trigger a resend.

Requested timeout is limited to 1–180 seconds, with the source +3-second agent
allowance and a 190-second HTTP budget. The existing 1 MiB NATS reply limit
still applies. `NUSHELL_ENABLE_CONFIG` defaults to false and must parse as a
boolean when set. `DENO_DEFAULT_PERMISSIONS` defaults to `--allow-all` when
absent; an explicitly empty value is preserved. The 74 execution comparisons
include explicit runtime overrides and an early real callback from a simulated
agent. Source timeout/natsdown false successes become HTTP 400; malformed replies
become 502. Server and email execution remain unsupported.

Focused suites: `--script-execution-only --nats-url nats://127.0.0.1:54222`,
`--script-callbacks-only`, and `--winupdate-policy-only`. CI includes them.
No production execution, routing change or deployment accompanied this tranche.

Async `forget` shares expansion, payload and committed audit/history with `wait`.
Its single publish has a 10-second budget; HTTP success confirms broker acceptance,
not execution. Known pre-send failures return 503, ambiguous delivery returns 502;
neither retries nor removes history. `--async-script-execution-only` with
`--nats-url` covers 49 contracts, including early/repeated callbacks and no subscriber.

The synchronous `note` mode saves the returned text unchanged as an agent note
with the initiating user as author; null becomes SQL NULL. Other reply types and
NUL characters return 502 without a note. Transport failures do not create notes;
a note insertion failure retains the committed execution history and never
resends the script. Opted-in callback-driven notes use the completion contract below.
`--script-notes-only --nats-url nats://127.0.0.1:54222` verifies 50 contracts.

Synchronous `collector` output writes to the agent, site or client selected by
the custom-field definition. Text, number, date and single-choice fields store
the trimmed string; multiple-choice fields split on commas, preserving empty
entries and internal spaces. Any nonempty checkbox string is true, including
`false`, matching Django. Choose the entire trimmed output or its last trimmed
line with the required boolean `save_all_output`.

Field/target validation happens before dispatch and is repeated under database
locks after the reply, with a five-second lock-wait limit. Changed definitions or tenant assignments are rejected;
failed local writes retain execution history and never resend the command.
Permissions follow the existing script permission and agent scope, including
parent site/client fields. Collector callbacks use the same conversion rules. Go serializes
collector writes, but mixed Django writers do not follow these locks and can
still create duplicate site/client values; existing duplicates are rejected.
Use `--script-collectors-only` with the local `--nats-url` for 173 contracts,
including simultaneous writes to absent site/client values and duplicate rejection.

### Asynchronous note completion

`output="note_async"` is an explicit Go extension; synchronous `note` is unchanged.
Apply `migrations/002_script_note_completion.sql` before enabling it. Without the
table the mode returns 501 before creating execution records or sending commands.
New histories and their pending completion marker commit before the one bounded
publish. Broker acceptance does not mean completion, and dispatch is never retried.

The callback binds token, URL, history and captured agent identity, then atomically
stores the result, a note authored by the agent-token user, and its completion.
The full accepted payload is compared as JSONB: identical redelivery returns 200
without writes, changed results return 409. Missing fields differ from explicit
null; object key order does not matter. Deleting the note preserves the completed
marker, so a replay cannot recreate it. Deleting history removes its marker.
Old histories are not inferred or backfilled; combined collector/note callbacks
remain unsupported. Run `--note-completion-only` with the local `--nats-url` for
14 schema checks and 24 end-to-end contracts.

Keep callbacks for these histories routed to Go during rollback or fence/drain
them first: Django ignores the marker and would create duplicate notes on replay.
No production migration, routing change or deployment has been performed.

## Remaining port

1. Complete accounts: SSO, additional login input/header/settings parity and
   secret-key rotation.
2. Agent deployment (`/clients/deployments/`), agents and API v3/v4/beta.
   Remaining core routes: `/core/dashinfo/` (GitHub version lookup, code-sign check),
   `emailtest`, `smstest`, `servermaintenance`, `clearcache`, `status`, `v2/status`,
   `codesign` PATCH/POST, `schedules`, `urlaction/run` and `run/test`, `openai/generate`,
   `ai-chat*`, `webtermperms`, `serverscript/test`.
   Agent reads still missing: `GET /agents/<agent_id>/` (AgentSerializer with
   applied policies/patch policy), `/agents/push-token/`, `/agents/freebsd-agent/<goarch>/`,
   other NATS/Mesh-backed reads (meshcentral,
   webvnc) plus agent writes other than notes, WMI refresh, process termination,
   power commands and registry operations.
3. Check/task mutations other than single-agent check execution, automation policy writes,
   remaining script execution modes, software removal, Windows update
   installation/scheduling, alert creation/template writes and remaining core settings,
   including signals and model-side effects.
4. QDT inventory, SNMP/probes, reports/rendering/delivery, Matrix, push and MCP.
5. Remaining Celery task replacement, persisted schedules, NATS and further Mesh
   integration, all four WebSocket routes and their authentication.
6. Full settings compatibility, files/templates, operational commands, database
   migrations, install/update/backup/restore and deployment/cutover validation.

Each completed flow needs a comparison against Django, including authorization,
validation, serialization and side effects. Route registration alone does not
count as a port. Current tests do not establish full-backend compatibility.
