# Isolated Go staging

The active test stack is Proxmox CT107 (`trmm-staging`) on `192.168.1.99`.
The container currently leases `192.168.1.85` by DHCP. Reserve the lease before
relying on this address long term. Access is limited to the LAN/VPN.

| Host | Service |
| --- | --- |
| rmm2.q-dt.de | Static frontend |
| api2.q-dt.de | Go API on 127.0.0.1:18082, with Go dashboard WebSocket |
| mesh2.q-dt.de | Separate MeshCentral on 127.0.0.1:14430 |

All API paths go to Go. There is no Python API, Django fallback or Celery
runtime in CT107. PostgreSQL16, Redis, NATS, Mesh and credentials are independent.
Production rmm.q-dt.de is not routed here and must not be modified.

Use `lxc_setup.py`, `lxc_mesh.py`, and `lxc_proxy.conf` for this topology.
The older `bootstrap.py`, `install_runtime.py`, `staging_settings.py` and
`go_routes.map` describe an abandoned same-host mixed-runtime attempt; do not
use them for this test stack. Its separate services on the production host
were stopped; leftover files and its separate database were not deleted.

## Runtime and updates

Services: trmm-go, trmm-mesh, nginx, postgresql, redis-server, nats-server.
Environment: `/etc/trmm-staging.env` (root:trmm 0640).
Binary: `/opt/trmm/bin/trmm-go`. Copy a new binary to `.next`, rename, then
restart only `trmm-go` through `pct exec 107` on Proxmox. Do not rerun schema
initialization against a populated database.

nginx forwards WebSocket upgrades on `/ws/`; access logging is disabled for
that location to avoid logging query-string session tokens.
`TLS_CERT_FILE=/etc/trmm-staging-cert.pem` is a public certificate copy readable
by the Go service. Refresh it when renewing the actual TLS certificate.

The DNS-01 certificate expires 2026-12-21. Renewal is not automated; see
README_ACME.md. Private TLS keys stay root-readable only.

## Current functional limits

Dashboard config/count stream, SNMP device/alert/latest/preset/probe reads,
inventory asset/profile/options reads, report options/configuration reads and
alert channel options have native Go handlers.
The Allauth config endpoint advertises no SSO providers. Unsupported server
scripts, web terminal, SSO and AI are disabled in dashboard capabilities.

The agent installer explicitly returns HTTP501: a usable installer requires
Go enrollment, Mesh agent delivery, agent configuration/check-in and individual
NATS credentials. These are not complete. No real agent is enrolled here.
Inventory writes, encrypted documents and SNMP scan/poll operations must not be
assumed migrated merely because their list views load.
Report generation, configuration writes and delivery also remain unported.
Server maintenance is implemented and tested locally, but its final deployment
is pending: the Keeper SSH socket stopped accepting connections before upload.
It supports transactional database pruning with its existing permission; NATS
reload and orphaned-task removal return explicit HTTP501. Deployment checks do
not execute maintenance or delete records.

The copied frontend bundle `eb0c4690.js` required a targeted initialization-order
fix in SnmpDeviceForm. `fix_snmp_form_bundle.py` applies it with unique-anchor
checks. The local frontend source is a different revision; do not replace the
whole deployed frontend from that checkout as part of this small fix.

Credentials are in protected local temporary files and root-only container
files, never in this repository. `testuser` has test-environment admin rights.
