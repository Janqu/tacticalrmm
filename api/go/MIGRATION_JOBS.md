# Background jobs: migration inventory

Repository audit, 2026-09-22. This is a code inventory and proposed migration order, **not a deployment record**. The ownership board is [MIGRATION_WORKSTREAMS.md](MIGRATION_WORKSTREAMS.md); operational settings, service supervision, files, backup/restore and cutover remain with the root/integration workstream.

Implementation update: `cmd/scheduled-jobs` provides the one-shot
`resolve-pending-actions` job and `auto-approve-win-updates` job with dry-run
and bounded processing. All 22 pending-action and 12 auto-approve isolated
Django/Go comparisons passed. The inventory below describes the source and
initial gaps; these two jobs are implemented, while every other listed
scheduling family and the production timer remain pending.

The application declares **18 Beat entries, 53 decorated tasks (including `debug_task`), and 64 explicit `.delay()` producers in 20 application files**. No application `.apply_async()` call was found. Counts exclude virtual environments, migrations and tests. Dynamic task variables in alert handling and direct calls to decorated task functions are included in the family analysis below; they are not additional literal producers. Redis is both Celery broker/result backend and an application cache/lock store, so removing Celery does not imply that Redis can be removed.

## Actual periodic schedule

Source: [tacticalrmm/celery.py](../tacticalrmm/tacticalrmm/celery.py), `app.conf.beat_schedule`. Cron expressions below are `minute hour day month weekday`. Django `TIME_ZONE` is UTC; deployment overrides and the effective Celery timezone must be checked at cutover. Interval schedules are intervals, not wall-clock cron equivalents.

| Beat entry | Task | Current cadence |
|---|---|---|
| matrix-pending-notifications | alerts.tasks.dispatch_pending_matrix | `* * * * *` |
| qdt-report-deliveries | qdt_reports.tasks.send_due_reports | `* * * * *` |
| auto-approve-win-updates | winupdate.tasks.auto_approve_updates_task | `2 */8 * * *` |
| install-scheduled-win-updates | winupdate.tasks.check_agent_update_schedule_task | `5 * * * *` |
| agent-auto-update | agents.tasks.auto_self_agent_update_task | `35 * * * *` |
| remove-orphaned-tasks | autotasks.tasks.remove_orphaned_win_tasks | `50 */2 * * *` |
| agent-outages-task | agents.tasks.agent_outages_task | every 150 seconds |
| unsnooze-alerts | alerts.tasks.unsnooze_alerts | `10 * * * *` |
| core-maintenance-tasks | core.tasks.core_maintenance_tasks | `15 * * * *` |
| cache-db-fields-task | core.tasks.cache_db_fields_task | `*/3 * * * *` |
| sync-scheduled-tasks | core.tasks.sync_scheduled_tasks | `*/2 * * * *` |
| snmp-prune-readings | qdt_snmp.tasks.prune_old_readings | `17 3 * * *` |
| inventory-maintenance-digest | qdt_inventory.tasks.send_maintenance_due_digest | `30 6 * * *` |
| sync-mesh-perms-task | core.tasks.sync_mesh_perms_task | `*/4 * * * *` |
| resolve-pending-actions | core.tasks.resolve_pending_actions | every 100 seconds |
| resolve-alerts-task | core.tasks.resolve_alerts_task | every 80 seconds |
| trmm-scheduler | core.tasks.scheduled_task_runner | `* * * * *` |
| trmm-reports-scheduler | ee.reporting.tasks.scheduled_reports_runner | `* * * * *` |

## Job families and dependencies

Except for Mesh described below, no independent Go worker/periodic implementation of these families exists in the audited tree. Go read endpoints, CRUD, agent command transport and callbacks cover parts of their dependencies; they are not replacements for their schedulers.

| Family and decorated tasks | Source / dependencies and migration boundary |
|---|---|
| Pending resolution: `resolve_pending_actions` | [core/tasks.py](../tacticalrmm/core/tasks.py): pending `agentupdate` rows, agent version/status and `LATEST_AGENT_VER`. DB-only; first proposed slice below. |
| Alert lifecycle: `unsnooze_alerts`, `cache_agents_alert_template`, `prune_resolved_alerts`, `resolve_alerts_task`, `agent_outages_task` | [alerts/tasks.py](../tacticalrmm/alerts/tasks.py), [core/tasks.py](../tacticalrmm/core/tasks.py), [agents/tasks.py](../tacticalrmm/agents/tasks.py). Inherited policies/templates, check/task results, maintenance/snooze rules, DB flags, cache, Redis locks; lifecycle calls fan out into notification/remediation. Go alert reads/writes are not lifecycle evaluation. |
| Notification delivery: `agent_outage_email_task`, `agent_recovery_email_task`, `agent_outage_sms_task`, `agent_recovery_sms_task`; `handle_check_email_alert_task`, `handle_check_sms_alert_task`, `handle_resolved_check_email_alert_task`, `handle_resolved_check_sms_alert_task`; `handle_task_email_alert`, `handle_task_sms_alert`, `handle_resolved_task_email_alert`, `handle_resolved_task_sms_alert` | [agents/tasks.py](../tacticalrmm/agents/tasks.py), [checks/tasks.py](../tacticalrmm/checks/tasks.py), [autotasks/tasks.py](../tacticalrmm/autotasks/tasks.py), dynamic dispatch in [alerts/models.py](../tacticalrmm/alerts/models.py). SMTP/SMS credentials, repeat intervals, current alert state and per-channel bookkeeping. Preserve delayed-state rechecks; do not mechanically retry ambiguous sends. |
| Matrix: `deliver_matrix_notification`, `dispatch_pending_matrix` | [alerts/matrix.py](../tacticalrmm/alerts/matrix.py), [alerts/tasks.py](../tacticalrmm/alerts/tasks.py), `MatrixDelivery`, channel and GlobalKVStore credentials. Transaction-ID deduplication, row lock, failure-before-resolution ordering; immediate enqueue after commit, three retries with increasing 60-second steps. Minute sweep selects only unsent, enabled deliveries with empty error, up to 100; failed rows are not an unlimited backlog replay. Preserve disabled channels and operator control. |
| QDT reports: `send_due_reports` | [qdt_reports/tasks.py](../tacticalrmm/qdt_reports/tasks.py), [delivery.py](../tacticalrmm/qdt_reports/delivery.py). Owner permissions and site scope rechecked; locked claim with `skip_locked`, next occurrence advanced and committed **before** HTML rendering/SMTP. No automatic retry of ambiguous SMTP; status and optional Matrix notification afterwards. |
| Enterprise reports: `scheduled_reports_runner`, `email_report`, `prune_report_history_task` | [ee/reporting/tasks.py](../tacticalrmm/ee/reporting/tasks.py), [utils.py](../tacticalrmm/ee/reporting/utils.py). Separate report templates/schedules/history, per-report timezone, daily/weekly/monthly/DOW recurrence, 55-second recent-run guard, render dependencies and email enqueue. Must not merge with QDT report state implicitly. |
| SNMP: `prune_old_readings` | [qdt_snmp/tasks.py](../tacticalrmm/qdt_snmp/tasks.py): 90-day readings retention under Redis lock. **Polling itself is an agent AutomatedTask**, provisioned by [provisioning.py](../tacticalrmm/qdt_snmp/provisioning.py) after commit, not a Beat poller. Requires probe installation/task scheduling, scoped authenticated ingestion, preset/OID support, secrets and old-probe schedule removal. Subnet discovery is request-triggered NATS; probe uses an eight-thread executor. |
| Inventory: `send_maintenance_due_digest` | [qdt_inventory/tasks.py](../tacticalrmm/qdt_inventory/tasks.py): 30-day lookahead, includes overdue, excludes retired/disposed, `*_notified_for` date deduplication; updates notification markers only after successful SMTP. Inventory/source linking and encrypted files are separate synchronous [views.py](../tacticalrmm/qdt_inventory/views.py)/[attachments.py](../tacticalrmm/qdt_inventory/attachments.py) work; no discovered attachment worker. |
| Windows updates: `auto_approve_updates_task`, `check_agent_update_schedule_task`, `bulk_install_updates_task`, `bulk_check_for_updates_task` | [winupdate/tasks.py](../tacticalrmm/winupdate/tasks.py). Effective patch policy/overrides, severity/approval state, agent timezone and online checks, NATS scans/installs, reboot semantics and callbacks. Existing Go update reads/policy writes do not implement scheduled approval/install. Execution belongs to the updates workstream. |
| Agent updates/recovery: `send_agent_update_task`, `auto_self_agent_update_task`, `bulk_recover_agents_task` | [agents/tasks.py](../tacticalrmm/agents/tasks.py). Signed/distributed binaries and tokens, eligible platform/version selection, NATS, pending rows and recovery commands. Metadata/version endpoints do not send updates. Installation/update operations and deployment ownership remain root; API execution coordinated with updates workstream. |
| Automation: `create_win_task_schedule`, `modify_win_task`, `delete_win_task_schedule`, `run_win_task`, `remove_orphaned_win_tasks`, `run_win_policy_autotasks_task`, `sync_scheduled_tasks`, `scheduled_task_runner` | [autotasks/tasks.py](../tacticalrmm/autotasks/tasks.py), [models.py](../tacticalrmm/autotasks/models.py), [automation/tasks.py](../tacticalrmm/automation/tasks.py), [core/tasks.py](../tacticalrmm/core/tasks.py). Inherited/excluded policies, TaskResult sync/run states and locks, Windows scheduler reconciliation versus server-scheduled POSIX tasks, timezone/DST/recurrence, callbacks and collector/note effects. POSIX runner marks running/locked and dispatches NATS inside its transaction; migration needs durable dispatch ownership and an explicit ambiguity policy. Go inherited-task reads do not execute or reconcile tasks. |
| Script/command batches: `bulk_command_task`, `bulk_script_task`, `run_script_email_results_task` | [scripts/tasks.py](../tacticalrmm/scripts/tasks.py), [agents/tasks.py](../tacticalrmm/agents/tasks.py). Agent selection, NATS/history, script content/args, execution timeout, mail results, collector/note callbacks. Go single-agent raw command and bounded history callback are partial prerequisites only; scripts workstream owns remaining execution. |
| Maintenance: `core_maintenance_tasks`, `prune_check_history`, `prune_agent_history`, `prune_debug_log`, `prune_audit_log`, `clear_faults_task` (+ report/alert pruners above) | [core/tasks.py](../tacticalrmm/core/tasks.py), [checks/tasks.py](../tacticalrmm/checks/tasks.py), [agents/tasks.py](../tacticalrmm/agents/tasks.py), [logs/tasks.py](../tacticalrmm/logs/tasks.py). Configured retention, expired AutomatedTask deletion/hooks, orphan check history and fault cleanup. Destructive data retention needs bounded transactions and counts; rollback cannot resurrect deleted data. |
| Cache aggregation: `cache_db_fields_task` | [core/tasks.py](../tacticalrmm/core/tasks.py): inherited check/task state, agent/site/client failure aggregation and Redis lock/cache. Go explicit invalidation and fresh policy reads do not replace every cached aggregate producer or consumer. |
| Mesh: `sync_mesh_perms_task` | [core/tasks.py](../tacticalrmm/core/tasks.py). Implemented Go reconciliation/queue is described below; mixed Django producers still require coordinated ownership. |
| Diagnostic: `debug_task` | [tacticalrmm/celery.py](../tacticalrmm/tacticalrmm/celery.py). Prints the Celery request. No production migration dependency unless operational callers depend on it. |

## Explicit enqueue producers

This compact map covers all 64 `.delay()` call sites; line numbers are audit-time anchors. Tasks can also call ordinary helper functions or decorated tasks synchronously, so transport and model hooks must be traced before moving each family.

| Producer sources (relative to `api/tacticalrmm`) | Enqueued families |
|---|---|
| `accounts/views.py:283,304,314,395,401`; `agents/views.py:333,359`; `apiv3/views.py:90,575`; `core/views.py:105`; `ee/sso/adapter.py:32` | Mesh permission reconciliation |
| `alerts/views.py:221,254,262`; `automation/models.py:55,57`; `clients/models.py:60,138`; `core/models.py:213`; `apiv3/views.py:577` | Effective alert-template cache rebuild |
| `alerts/models.py:480,502,724,739` | Dynamic email/SMS failure/recovery tasks for availability, checks and automated tasks |
| `alerts/matrix.py:41`; `alerts/tasks.py:56` | Matrix after-commit delivery and recovery sweep |
| `autotasks/views.py:58,97,100,121,125`; `automation/views.py:98`; `core/views.py:204`; `qdt_snmp/provisioning.py:209` | Create/delete/run task, remove orphan tasks, policy task execution and SNMP poll installation |
| `agents/views.py:525`; `core/views.py:339`; `agents/management/commands/update_agents.py:26` | Agent update dispatch |
| `agents/views.py:1026,1221,1244,1261,1266,1310` | Script email, bulk command/script, bulk install/scan updates, recovery |
| `ee/reporting/views.py:182`; `ee/reporting/utils.py:810` | Report email delivery |
| `core/tasks.py:108,112,116,120,124,128,131` | Configured prune/fault child tasks |
| `core/management/commands/run_all_tasks.py:21-32` | Manual producer for 12 periodic families; must be disabled/adapted per migrated family, not forgotten when Beat is changed |

## Other asynchronous/background surfaces

- **Push:** [alerts/signals.py](../tacticalrmm/alerts/signals.py) calls [agents/push.py](../tacticalrmm/agents/push.py) on alert creation; Firebase multicast and dead-token pruning are synchronous signal side effects, not Celery jobs. Migration needs recipient-scope review and preservation of token pruning; absent Go signal handling must not be mistaken for completed notification support.
- **MCP:** [qdt_mcp/executor.py](../tacticalrmm/qdt_mcp/executor.py) executes tools synchronously with per-user credentials/context, including an async bridge. [server.py](../tacticalrmm/qdt_mcp/server.py) delegates into APIs. No separate MCP Beat task was found. API parity, permission/read-only metadata, script/automation/alerts tools and downstream job availability must migrate together.
- **WebSocket/PTY:** [agents/consumers.py](../tacticalrmm/agents/consumers.py), [core/consumers.py](../tacticalrmm/core/consumers.py), [agents/models.py](../tacticalrmm/agents/models.py) retain async streams, cancellation waiters, dashboard loops, PTY subprocesses and threads. These are connection lifecycle work, not cron. Root owns integration and process supervision.
- **Read/model hooks:** [logs/signals.py](../tacticalrmm/logs/signals.py) completes expired scheduled-reboot pending actions during model initialization. This is distinct from `resolve_pending_actions`, which only resolves agent updates. Inventory/agent/check callbacks can have database and notification effects outside task decorators.

## Existing Go worker and migration gap

[cmd/mesh-sync](cmd/mesh-sync/main.go), [internal/mesh/jobs.go](internal/mesh/jobs.go), [sync.go](internal/mesh/sync.go) and [001_mesh_sync.sql](migrations/001_mesh_sync.sql) implement full reconciliation plus durable, coalesced generations. Mutations enqueue in their DB transaction; the worker polls every five seconds, acknowledges only the observed generation, retains failed work and delays retry 30 seconds. `--worker --once` and `--dry-run` exist. Reconciliation is at least once, bounded by context, with PostgreSQL advisory locking.

That lock **does not coordinate with Django's Redis Mesh lock**. `TRMM_DISABLE_MESH_SYNC_TASK` gates each implementation and `sync_mesh_with_trmm=false` means removal of managed remote accounts, not harmless pausing. Deployment must leave exactly one synchronizer active while accounting for all old event producers and periodic reconciliation. The Go durable queue alone does not observe Django-only mutations; the existing periodic Mesh trigger cannot simply disappear until those producers are migrated or explicitly bridged.

The audited Go commands are `api` and `mesh-sync`; no generic scheduler, Celery-compatible consumer, Matrix/report worker or maintenance timer is present. Existing agent command handlers/callbacks are request-driven and do not drain Celery messages. Source files are implementation evidence, not proof of production cutover.

## Smallest next implementation: resolve_pending_actions

Proposed scope, **not implemented by this document**:

1. Add a one-shot Go job with an explicit job selection, DB connection, latest-agent-version configuration, injectable clock and dry-run candidate count. Let the root deployment workstream supervise its 100-second schedule; do not introduce a generic workflow framework for one DB-only job.
2. Match [core/tasks.py:resolve_pending_actions](../tacticalrmm/core/tasks.py): select only `action_type='agentupdate' AND status='pending'`; complete only agents whose PEP 440 parsed version equals configured `LATEST_AGENT_VER` and whose source `Agent.status` is online. It is equality, not minimum version or “update command acknowledged”. Existing minimum-version gates are not a version-equality implementation.
3. Source [Agent.status](../tacticalrmm/agents/models.py) compares `last_seen` with offline/overdue boundaries in minutes. NULL means offline. Equality at boundaries, unusual threshold ordering and future timestamps must be covered explicitly; do not silently simplify to a single strict cutoff. Invalid version currently aborts the Python job before its bulk update: choose/document an equally atomic error policy before writing.
4. Use a bounded transaction and a single-owner job lock; recheck pending/type/agent eligibility under transaction before changing only `status`. No NATS, email, audit event, token mutation, scheduled-reboot expiry, or generic pending-action cleanup. Reruns are idempotent. Report selected/updated/skipped counts and duration without secrets.
5. Differential tests: matching/nonmatching normalized versions, local/pre/post/dev/epoch forms, invalid versions, NULL last_seen, exact clock boundaries, future last_seen, pending/completed/other-action rows, concurrent callback/status change, cancellation and forced SQL failure. Run only against the isolated contract DB; dry-run must not write.
6. Integration gate: root compares dry-run candidates, disables only this Python Beat/manual producer, drains any in-flight copy, enables the Go timer and verifies counts. On rollback stop Go first and restore the Python producer. Already completed valid rows remain completed; this DB-only transition does not need reversal.

After this slice, small DB-only unsnooze/prune work can proceed independently with retention review; auto-approval precedes remote scheduled installs. Matrix/report delivery needs durable claim and ambiguity semantics before transport cutover. Automation/SNMP polling depends on task execution and callbacks, not just a new timer.

## Implemented: auto-approve-win-updates

`cmd/scheduled-jobs --job auto-approve-win-updates` mirrors
`winupdate.tasks.auto_approve_updates_task`. It respects
`TRMM_DISABLE_APPROVE_UPDATES_TASK`, prunes and approves each agent under
separate commits (approval errors skipped), then publishes `getwinupdates` to
online agents at PEP 440 version >= 1.3.0 in chunks of 40 with a configurable
pause. An invalid version on an online agent aborts the scan phase after
approvals have committed, matching Django. Session advisory locking prevents
concurrent Go runs. Dry-run reports eligibility without writes or publishes.
No production timer is enabled; disable the Django Beat entry and drain it
before scheduling Go. Focused flag:
`--winupdate-auto-approve-only --jobs-binary ... --nats-url ...`.

Scheduled install (`check_agent_update_schedule_task`) remains pending.

## Ownership, cutover and rollback

| Responsibility | Owner / acceptance evidence |
|---|---|
| Jobs inventory, future QDT inventory/documents, SNMP/probes, QDT reports, Matrix/push and MCP API/job migration | This workstream, coordinated through the master board. Deliver family-specific source contract, producer map, tests and recovery behavior before implementation is marked complete. |
| Script execution and relevant callbacks | Scripts workstream; command/history prerequisites shared through integration. |
| Windows update approval/execution/callbacks | Updates workstream; agent install/distribution deployment remains root. |
| Settings, units/timers, routing, persistent files/keys, credentials, backup/restore, deployment and cutover | Root/integration. No production changes are authorized by this inventory itself. |
| Per-family handover | Implementation owner supplies tests, queued/in-flight state and observability; root confirms one owner for both periodic and event-triggered execution. |

For every family: disable/redirect **all** old producers, stop their schedule, inspect in-flight/reserved/retry work, then enable the replacement. Do not consume arbitrary Python/Celery serialized messages from Go. Preserve durable domain records and explicitly migrate or drain payloads; do not flush Redis globally. Mixed operation is allowed across independent families, not two active dispatchers for one remote-effect family.

Rollback stops the Go dispatcher before restoring Django producers. Preserve queue generations, notification transaction IDs, attempt markers, report claims, TaskResult locks and pending histories. A timeout/crash can mean the remote action already happened: inspect acknowledged/domain state before retrying commands, SMTP or reports. Do not automatically replay a Matrix backlog merely because a token was repaired. Retention deletion requires backup recovery, not a reverse job.

Celery can be removed only after all 18 schedules, all producer groups above, dynamic notification dispatch and manual commands have an owned replacement or explicit retirement, and the source-only task queues are drained. Redis removal is a separate cache/locking migration.
