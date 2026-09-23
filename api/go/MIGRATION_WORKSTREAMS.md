# Go migration: assigned workstreams

Updated 2026-09-22. This board assigns the remaining migration scope; assignment
does not mean implementation or production readiness. Three agents can work in
parallel with the integration owner. The three source-checked plans are complete.
Pure script expansion, bounded NATS Publish and the one-shot pending-agent-update
job are implemented and locally verified. The supported DB resolver subset,
Windows-update cleanup and scan/callback flow are now also implemented.
Subsequent packages remain queued
until dependencies and file ownership permit implementation.

| Owner | Current package | Queued scope |
| --- | --- | --- |
| `go_alerts` | [Stored scripts and completion](MIGRATION_SCRIPTS.md) | Accounts/SSO; remaining core API; check/task/automation mutations; alert creation/templates and model side effects |
| `go_automation` | [NATS publish and Windows updates](MIGRATION_UPDATES.md) | Agent enrollment/deployment and v3/v4/beta protocol; remaining agent actions and software removal; Mesh, WebSockets, WebVNC and agent push-token integration |
| `go_script_writes` | [Scheduled jobs and Celery retirement](MIGRATION_JOBS.md) | QDT inventory and encrypted attachments; SNMP/probes; reports/rendering/delivery; Matrix/push notification delivery; MCP |
| Root | Integration, coverage and sequencing | Settings/files/templates; schema migration; operational commands; installation/update/backup/restore; deployment and rollback validation |

Latest validation: 394 Python/Go script-transformation comparisons plus 17
explicit unsupported-case checks; 22 pending-job DB comparisons; 82 existing
raw-command/callback comparisons after the transport refactor. Full Go race
tests (including the local broker), `go vet` and formatting checks passed.
CI now runs the new suites. No production timer, script route or deployment
was enabled. The latest tranche adds 181 resolver, 26 cleanup and 93 scan/callback
comparisons, plus 22 job and 420 endpoint-management regression checks; full
Go race tests and vet passed. The next tranche is now also complete: 76 synchronous
script execution, 54 plain script callback and 42 effective update-policy cases
passed, alongside existing command, policy/log and endpoint regressions. Full
race tests and vet passed. The following tranche adds 51 async script and 35 update-result comparisons,
with 76 synchronous and 92 scan regressions passing. Next: separately
replay-safe collector/note completion; update installation only with its full
completion/reboot contract. Unsupported property forms and installation/reboot
completion callbacks remain pending. No production deployment or schedule was changed.

## Scope cross-check

These packages cover the six remaining areas listed in `README.md`. Existing Go
reads or CRUD handlers are reused; their presence does not cover execution,
signals, callbacks or scheduling automatically.

- Identity/core owner: `tacticalrmm/accounts`, `ee/sso`, `core`, `checks`,
  `autotasks`, `automation`, `alerts`. Include the remaining core routes listed
  in README, agent-detail policy projection with the agent owner, cache
  invalidation and model hooks. Task scheduling execution belongs to the jobs
  owner; its API mutations belong here.
- Agent/transport owner: `tacticalrmm/agents`, deployment routes in `clients`,
  `apiv3`, `apiv4`, `beta/v1`, `software`, `winupdate`, and the consumers in
  `agents/consumers.py` and `core/consumers.py`. Script callbacks belong to the
  scripts owner; update callbacks belong to this owner. Reuse one transport.
- Jobs/QDT owner: `tacticalrmm/tacticalrmm/celery.py`, task producers throughout
  the application, `qdt_inventory`, `qdt_snmp`, `qdt_reports`, `ee/reporting`,
  Matrix delivery under `alerts`, and `qdt_mcp`. Preserve existing encrypted
  attachment data and access controls, report permissions and probe semantics.
  Notification delivery is separate from alert configuration CRUD.
- Integration owner: settings compatibility and Django/Go mixed-operation
  behavior; `install.sh`, `update.sh`, `backup.sh`, `restore.sh`, `ansible`,
  `docker`, database migrations and service/proxy configuration. Verify recovery
  and scheduler ownership before any production cutover.

## Execution order and handoffs

1. Finish source checks and freeze each detailed package. Assign concrete files
   before implementation; shared server routing, test-runner flags and top-level
   documentation remain owned by root.
2. Script expansion and synchronous execution, transport Publish, and the first
   replay-safe scheduled job can then proceed independently. Publish must be
   tested before update or asynchronous-script producers use it.
3. Integrate each producer with its authenticated completion path. Test history
   visibility before dispatch, tenant scope, failure rollback, ambiguous delivery
   and duplicate callbacks using isolated services and simulated agents.
4. Take remaining queued API/QDT packages as slots become available. Define their
   runnable source comparisons before claiming completion; unsupported modes
   stay explicitly unsupported or routed to Django.
5. Inventory and replace each remaining job/producer with one active scheduler
   owner. Do not stop Celery globally because selected jobs work in Go.
6. Root performs the combined validation and records which routes and workers
   can be switched, plus rollback steps. No production deployment is part of this
   allocation tranche.

Completed baseline: raw command execution and plain command-history callbacks;
82 dedicated contracts plus 158 core and 419 endpoint-management checks passed,
along with `go test -race ./...` and `go vet ./...`. See `MIGRATION_NEXT.md` and
README for the other completed slices and their limits.

Aktueller Teilabschluss: synchroner Skript-Notizmodus (50 Vergleiche) und
Update-Abschluss ohne Neustart (36 Vergleiche). Callback-Notizen/Collector
und Update-Abschluss mit Neustart bleiben offen; dafür fehlt dem Agent-Protokoll
eine Ausführungsidentität. CI enthält beide neuen fokussierten Suiten.

Abschlussprüfung dieser Runde: 336 Differentialvergleiche bestanden
(50 Notiz, 36 Abschluss, 75 synchron, 50 async, 34 Einzelresultate, 91 Scan),
zusätzlich vollständige Go-Race-Tests, go vet und Formatierung. Keine Produktion
verändert. Weggefallene 501-Erwartungen erklären die kleineren Regressionstestzahlen.

Collector-Tranche abgeschlossen: 173 neue Collector-Vergleiche einschließlich
paralleler Standort-/Kundenwerte und 173 Regressionen (74 synchron, 49 async,
50 Notiz) bestanden. Vollständige Go-Race-Tests, go vet und Formatierung bestanden.
CI/Dokumentation ergänzt. Noch offen: Callback-Collector/Notizen, E-Mail- und
Serverausführung sowie Installationsabschluss mit Neustart. Kein Deployment.

Collector-Callbacks abgeschlossen: 156 neue Vergleiche, 54 einfache Skript-Callbacks,
82 Befehls-/Callback- und 49 Async-Regressionen bestanden (341 insgesamt).
Go-Race-Tests, go vet und Formatierung bestanden; CI ergänzt. Feld und Verlauf
werden atomar gespeichert, die Sperrreihenfolge entspricht der Feldlöschung.
Notiz-Callbacks bleiben 501; der dokumentierte nächste Schritt benötigt eine
explizite Migration und eine Abschlusskennung ab Producer-Erstellung. Keine
Schemaänderung und kein Produktionsdeploy in dieser Runde.

Notiz-Abschluss umgesetzt: expliziter Go-Modus note_async mit vor Versand
gespeicherter Abschlusskennung und wiederholungssicherem Callback. Migration
002 ist vorbereitet, nicht produktiv angewandt. 24 neue Ablaufvergleiche und
14 Schema-Prüfungen bestanden; 50 synchrone Notiz-, 156 Collector-Callback- und
54 einfache Callback-Regressionen ebenfalls (298 Prüfungen insgesamt).
Go-Race-Tests, go vet und Formatierung bestanden. Altbestände ohne Marker sowie
kombinierte Collector-/Notiz-Callbacks bleiben gesperrt. Rollback-Routing darf
diese Go-Histories nicht unkontrolliert an Django weiterreichen. Kein Deployment.

Manuelle Windows-Update-Installation umgesetzt: Bereinigung, Auto-Approval und
GUID-Auswahl vor Publish; POSIX-Ablehnung vor Mutation; 128 Scan-/Install-/
Callback-Vergleiche bestanden. Reboot-pflichtiger Abschluss bleibt 501. Kein
produktives Routing und kein Scheduler-Cutover.

Periodische Auto-Freigabe umgesetzt: `scheduled-jobs --job auto-approve-win-updates`
mit Dry-Run, Disable-Flag, Session-Lock, Chunk-Publish und 12 Vergleichen.
Geplante Installation und Produktionstimer bleiben offen. CI enthält
`--winupdate-auto-approve-only`.
