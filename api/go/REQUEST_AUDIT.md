# Frontend and agent request audit

Scope: local QDT RMM Docker stack, 2026-09-23. Production and api2 were not
changed. HTTP observations are distinct from source inspection. No agent
commands, installations, updates or authenticated agent callbacks were executed.

## Additional frontend HTTP checks

Authenticated GET requests through localhost:8088:

| Path (after frontend `/api` prefix) | Status |
| --- | --- |
| `/qdt_inventory/assets/?page=1` | 200 |
| `/qdt_inventory/options/` | 200 |
| `/qdt_inventory/profiles/` | 200 |
| `/qdt_inventory/sources/` | 404 |
| `/qdt_inventory/export/` | 404 |
| `/qdt_reports/options/` | 200 |
| `/qdt_reports/configurations/` | 200 |
| `/automation/policies/` | 200 |

InventoryManager also calls asset detail/history, from-agent, import and profile
writes. `internal/httpapi/inventory_reads.go` only registers the three list/options
routes above. These other operations are missing by source inspection; no fake
asset ID was used to confuse a missing object with a missing route.

Previously confirmed frontend 404s: `/clients/deployments/`,
`/core/ai-chat/sessions/`, `/qdt_reports/deliveries/`, `/reporting/assets/`,
`/reporting/assets/all/`, `/reporting/assets/download/`, `/reporting/queryschema/`.

## Agent HTTP contracts

Sources: sibling `rmmagent/agent` directory. Parameters below are placeholders.
The following method/path combinations are used by the agent but have no route
registered in the current Go API:

| Methods | Path | Caller |
| --- | --- | --- |
| GET, POST | `/api/v3/installer/` | install.go |
| POST | `/api/v3/meshexe/` | install.go |
| POST | `/api/v3/newagent/` | install.go |
| POST | `/api/v3/checkin/` | svc.go |
| GET | `/api/v3/{agent}/config/` | svc.go |
| GET | `/api/v3/{agent}/checkinterval/` | checks.go |
| GET | `/api/v3/{agent}/runchecks/` | checks.go |
| GET | `/api/v3/{agent}/checkrunner/` | checks.go |
| PATCH | `/api/v3/checkrunner/` | checks.go |
| GET, PATCH | `/api/v3/{task}/{agent}/taskrunner/` | agent.go |
| POST | `/api/v3/software/` | agent_windows.go |
| POST | `/api/v3/choco/` | choco_windows.go |
| POST | `/api/v3/syncmesh/` | agent.go |
| GET | `/api/v3/{agent}/meshreinstall/` | agent.go |

These callbacks ARE registered in Go (not end-to-end agent verified):

- POST/PATCH/PUT `/api/v3/winupdates/`
- POST `/api/v3/superseded/`
- PATCH `/api/v3/{history}/{agent}/histresult/`
- PATCH `/api/v4/{agent}/{pending_action}/chocoresult/`

### Proxy defect, independently confirmed

`docker/qdt-rmm/nginx.conf` strips `/api/` for the frontend. The agent itself
already includes `/api/v3/` or `/api/v4/`. Its callback therefore reaches Go as
`/v3/...` or `/v4/...`, which does not match the registered route.

Unauthenticated GET probes (callbacks require authentication before handling):

| Public path | Status |
| --- | --- |
| `/api/v3/winupdates/` | 404 |
| `/api/api/v3/winupdates/` | 401 |
| `/api/v3/1/audit-no-agent/histresult/` | 404 |
| `/api/api/v3/1/audit-no-agent/histresult/` | 401 |
| `/api/v4/audit-no-agent/1/chocoresult/` | 404 |
| `/api/api/v4/audit-no-agent/1/chocoresult/` | 401 |

The 401 proves the route/authentication boundary is reached, not callback success.
Fix the proxy routing for agent prefixes; do not change agents to double `/api`.

## NATS: source/configuration findings

- Agent `setupNatsOptions` authenticates with agent ID and agent token. Docker
  NATS currently only configures the service user `qdt-rmm`. Agent credentials
  are not provisioned. Do not distribute the service credential as a workaround.
- Agent defaults to TLS WebSocket port 443, path `natsws`. Local stack exposes
  HTTP port 8088, proxy path `/api/natsws`. It is not a ready agent endpoint.
- In agent.go, nonempty `ac.NatsProxyPath` and `ac.NatsProxyPort` are never copied
  into their local variables; only empty-value defaults are assigned. Custom
  overrides therefore do not take effect in this code.
- `checkin.go` publishes agent telemetry through NATS. The Go service currently
  implements outgoing request/reply and publish in `internal/agentbus`; there is
  no persistent telemetry subscriber in the application sources. Running a NATS
  broker alone does not store incoming inventory/heartbeat messages.

## Priority

1. Correct proxy routing, then implement installer/enrollment and agent identity.
2. Provision scoped NATS authentication and implement telemetry ingestion.
3. Implement config/check/task contracts and remaining callback ingestion.
4. Complete frontend inventory/reporting mutations and exports.

This is a request compatibility audit, not a claim of a complete migration or
a successful installed-agent integration test.
