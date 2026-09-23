# Next execution and scheduling slices

Ownership for all remaining areas is tracked in
[MIGRATION_WORKSTREAMS.md](MIGRATION_WORKSTREAMS.md).

Status: **slice 1 and bounded synchronous/asynchronous remote script execution are implemented**, updated 2026-09-22. Plain command/script-history, Chocolatey and Windows-update scan callbacks are integrated. Plain async execution and per-GUID update results are tested (51 and 35 cases). Synchronous note output and non-reboot update completion are also implemented (50 and 36 contracts). Synchronous collectors are now implemented; collector callbacks are also implemented; new Go-owned note callbacks are implemented via explicit note_async mode; manual Windows-update installation is implemented with POSIX rejection before mutation. Legacy/combined note callbacks and reboot completion remain pending. Keep unsupported routes or modes on Django until their complete slice passes its contract tests. These changes have not been deployed to production.

Foundation progress: bounded NATS Publish and the one-shot pending-agent-update
job are implemented and locally tested. Pure snippet/argument/environment
expansion and a read-only resolver for explicitly supported database fields are
also tested; unrestricted property resolution and remaining script execution modes are pending.
Manual Windows-update scan, transactional scan-result ingestion and superseded
callbacks, effective-policy/approval helpers and manual installation dispatch are
implemented; scheduled install and reboot-required completion remain pending. The first
two jobs do not replace the remaining scheduler or enable a production timer.

Paths below are relative to `api/`. Go files in pending slices are implementation targets, not existing capabilities. No production command was run for this review.

## Existing building blocks and limits

- `go/internal/agentbus/client.go` handles request/reply and bounded Publish, MessagePack validation, secure connection defaults, cancellation and bounded replies. Both operations reuse the same connection helper.
- `go/internal/httpapi/agents_reads.go` provides agent scope/history serialization; `scripts_reads.go`, `scripts_writes.go` and `script_snippets.go` provide script storage, not execution/template expansion. Reuse audit helpers, permission checks and `resolveAgentPolicies` rather than duplicate them.
- `go/internal/mesh/jobs.go`, `go/migrations/001_mesh_sync.sql`, and `go/cmd/mesh-sync/main.go` implement the only existing Go outbox: a singleton, coalescing MeshCentral reconciliation generation. Enqueue participates in the mutation transaction; acknowledgement cannot consume a newer generation. Its retry is deliberately at-least-once. **Do not reuse this table or its automatic retries for commands:** two requested executions cannot be coalesced, and a resend can repeat an installation, command or script. Reuse the transaction/acknowledgement pattern only where appropriate.
- `tacticalrmm/logs/models.py:PendingAction` and `agents/models.py:AgentHistory` are plain models, with no automatic BaseAuditModel audit. PendingAction's `logs/signals.py:handle_status` only marks existing scheduled-reboot rows completed on initialization. Creating a command history does not itself dispatch anything.

## 1. Single-agent synchronous raw command

**Source:** `tacticalrmm/agents/urls.py`, `agents/views.py:send_raw_cmd`, `agents/permissions.py:SendCMDPerms`, `logs/models.py:AuditLog.audit_raw_command`, and `apiv3/views.py:AgentHistoryResult.patch`.

**Contract:** POST `/agents/<agent_id>/cmd/` requires `can_send_cmd` and agent scope. Inputs are `cmd`, `shell`, `custom_shell` when selected, `timeout`, and `run_as_user`. Create AgentHistory with CMD_RUN, command text and username truncated to 50 characters; send `rawcmd`, timeout, history `id`, payload `{command,shell}`, and `run_as_user`. Request timeout is user timeout +2 seconds. Django returns the agent reply; literal `timeout` becomes an error and skips the explicit raw-command audit, otherwise it audits with requester IP. Explicitly reject transport failures/malformed replies rather than present `natsdown` as command output.

**Implemented:** one synchronous command with a validated 1–180 second timeout and a 190 second HTTP deadline. History commits before sending, allowing an immediate callback over a separate DB connection. No transaction remains open while waiting, and commands are never resent automatically. The Go v3 callback accepts only plain command results, binds both URL and history to the authenticated agent, and accepts plain script results and collector results and marked note histories while rejecting unmarked legacy note histories before mutation. Audit timing and post-send database failures are covered by local integration tests; atomic DB writes cannot undo the remote command.

**Targets:** `go/internal/httpapi/agent_rawcmd.go`, focused tests, `go/tools/compare_agent_rawcmd.py`; narrow `server.go` route/time-budget wiring. Reuse agentbus Request. Do not add terminal streaming here.

**Tests:** permission/scope/installer rejection without send; custom shell and Unicode; timeout bounds; callback sees committed history before reply; request failure retains history; exact audit payload/timing; malformed replies; callback re-delivery and cross-agent ownership. Use a fake/local broker, never a real agent.

**Cutover gate:** callback persistence and ownership verified end-to-end; reverse-proxy and request deadlines cover the maximum advertised command timeout; no hidden retries in proxy/client/transport.

## 2. Single-agent synchronous stored script

**Implemented boundary:** remote `output="wait"`, supported template/DB lookups,
1–180 second requested timeout, source runtime flags, atomic pre-dispatch
audit/history and plain script-result callbacks. 76 execution and 54 callback
comparisons passed. NATS replies retain their 1 MiB limit; callback bodies retain
the API's 4 MiB rejection limit rather than Django's larger-body truncation.
The remaining modes and properties below are not implicitly enabled.

**Source:** `agents/views.py:run_script`, `agents/models.py:Agent.run_script`, `scripts/models.py:Script.code`, `replace_with_snippets`, `parse_script_args`, `parse_script_env_vars`, and `tacticalrmm/utils.py:replace_arg_db_values`. Results arrive through `apiv3/views.py:AgentHistoryResult.patch`.

**Contract:** POST `/agents/<agent_id>/runscript/`, `can_run_scripts` plus scope, fields `script`, `output`, `args`, `env_vars`, `timeout`, `run_as_user`, optional `run_on_server`. First implement only `output="wait"`, remote execution. Reject unsupported modes before audit/history/send. Django audits script execution and creates SCRIPT_RUN history before dispatch. Payload is `runscript`, timeout=requested+3, parsed arguments, `{code,shell}`, history `id`, env vars, `nushell_enable_config`, and `deno_default_permissions`. Script model `run_as_user=true` overrides a false request. Return agent output.

**Smallest first slice:** implement template expansion with its actual source semantics, then synchronous execution. `Script.code` expands stored snippets; args and env values interpolate DB/custom-field values and apply shell-specific quoting. Do not silently send unresolved templates as a substitute for this dependency. Tests should cover greedy replacement, backslashes, missing snippets, falsey DB values, CMD quoting, and env values containing `=`. If a template form is deliberately unsupported, validate and reject it before any side effect.

**Targets:** `go/internal/httpapi/agent_script_execution.go`, a small script-expansion helper in that domain, corresponding unit tests and `go/tools/compare_agent_script_execution.py`. Reuse existing script persistence/projection and audit helpers.

**Tests:** script not found; actor scope; model run-as-user override; all supported shell payloads; callback committed visibility; template/custom-field data types; transport timeout; no execution on unsupported output/server mode. Callback tests must cover result truncation, nullable/deleted script relations and token-agent binding.

**Cutover gate:** no missing template or configuration behavior for routed requests. Server execution remains pending: it additionally depends on `core.utils.run_server_script`, `server_scripts_enabled`, `RunServerScriptPerms`, local executable/runtime isolation and process cancellation. It must not be enabled as a side effect of remote script support.

## 3. Async publish and background script completion

**Source:** `agents/models.py:Agent.nats_cmd(wait=False)` uses publish, flush, close; `Agent.run_script(wait=False)`; `agents/views.py:run_script` default, `email`, `collector`, and `note` branches; `agents/tasks.py:run_script_email_results_task`; `apiv3/views.py:AgentHistoryResult.patch`.

**Contract:** publishing successfully only means the broker accepted bytes, not that an agent executed them. The default script branch responds `<script> will now be run on <hostname>`. A callback later updates history, optionally writes a custom field or creates an agent note. Email mode currently delegates execution and delivery to Celery. Synchronous collector/note branches perform their DB writes after output; these are separate from callback-driven flags on history.

**Smallest first slice:** add bounded `Client.Publish` with MessagePack, flush and context handling, then enable only the existing asynchronous stored-script response. History/audit must commit before publish. No background goroutine that outlives request shutdown and loses untracked work. No automatic resend after an ambiguous flush/connection failure. Keep email mode on Django until durable execution and email delivery state are designed and tested.

**Targets:** extend `go/internal/agentbus/client.go` and its tests; extend script execution handler/tests. If durable queued execution becomes necessary, add one explicit command-job table and small worker with per-job identity/state; do not generalize the mesh singleton into a universal job framework. Preserve execution identity across retries and callbacks.

**Tests:** no subscriber; connect failure before publish; broker accepts message then disconnects before flush confirmation; cancellation; process shutdown; callback before handler response; duplicate callback must not create duplicate notes/emails. Test that ambiguous delivery does not trigger a second publish.

**Cutover gate:** documented delivery semantics and operator-visible ambiguous state. Exactly-once execution cannot be promised without agent-side deduplication. Durable scheduling must distinguish never-sent jobs from possibly-sent jobs. Collector writes, notes and email each require their own replay-safe completion boundary before routing those modes.

## 4. Manual Windows update scan, then install

**Source:** `winupdate/views.py:ScanWindowsUpdates.post`, `InstallWindowsUpdates.post`; `agents/models.py:delete_superseded_updates`, `approve_updates`, `get_patch_policy`, `get_approved_update_guids`; `apiv3/views.py:WinUpdates` and `SupersededWinUpdate`; existing Go `winupdates.go` and patch-policy handlers cover CRUD, not execution.

**Contract:** POST `/winupdate/<agent>/scan/` removes superseded local rows, publishes `getwinupdates`, returns the scan message. Source rejects POSIX here. POST `/winupdate/<agent>/install/` removes superseded rows, auto-approves according to effective patch policy, publishes `installwinupdates` with approved uninstalled GUIDs, returns installation message. Both require Windows-update permission and scope. Do not copy the install route's missing platform guard inadvertently.

**Smallest first slice:** scan + authenticated scan-results callback; then install + success/failure/reboot callbacks. Scan callback updates the highest-ID row for an existing GUID, creates otherwise, skips new rows without a usable KB ID, deletes stale uninstalled rows, and prunes superseded versions. Success callback updates downloaded/installed/result/date; failed callback marks result. Completion PUT updates agent.needs_reboot, consults reboot policy, may publish `rebootnow`, and logs. This callback is an execution endpoint, not mere data ingestion.

**Targets:** `go/internal/httpapi/winupdate_commands.go`, `winupdate_callbacks.go`, narrow shared effective-policy/supersedence helpers and contract tests. Reuse `resolveAgentPolicies`, current scope helpers and WinUpdate projection. Commit callback state and command prerequisites before remote operations.

**Dependencies:** effective policy can create a missing agent WinUpdatePolicy; first applicable policy is overlaid with agent overrides. Frequency override copies frequency/hour/days, not every schedule field. Auto-approval can overwrite non-approved actions for matching severities. Supersedence groups by KB and parses title `(Version|Versão ...)`. The source name `LooseVersion` aliases `packaging.version.Version`, so ordering follows PEP 440, not distutils. These behaviors need differential fixtures, not a generic version comparator assumption.

**Tests:** empty scans; duplicate GUID/KB/version titles; highest-ID update; existing installed-row preservation; scope; approval overlay; DB rollback before publish; callback retry; reboot required/always/never and ambiguous publish. Scan-result deletion must not partially commit on malformed payload. Compare intentional safety deviations separately.

**Cutover gate:** all three callback methods and superseded-update callback are routed consistently; post-install reboot cannot be duplicated by retry; existing Django periodic update jobs remain sole scheduler until slice 5 owns their schedule.

## 5. One scheduled job at a time, then Celery retirement

**Source:** `tacticalrmm/celery.py:app.conf.beat_schedule`; `winupdate/tasks.py:auto_approve_updates_task`, `check_agent_update_schedule_task`, bulk tasks; `core/tasks.py:sync_scheduled_tasks`, `scheduled_task_runner`, `resolve_pending_actions`; `autotasks/tasks.py:create_win_task_schedule`, `modify_win_task`, `delete_win_task_schedule`, `run_win_task`; `autotasks/models.py:AutomatedTask.save/delete`, `TaskResult`.

**Smallest first slice:** move only `core.tasks.resolve_pending_actions` to a bounded scheduled Go command: mark pending agent-update actions completed when the agent is online at configured latest version. This has no remote command and is replay-safe. Use the existing command/DB pattern, one scheduler owner, and explicit run logging. Next move update approval, then scheduled installs after slice 4. Keep each remaining beat entry and `.delay()` producer on Django until separately accounted for.

**Targets:** `go/cmd/scheduled-jobs/main.go`, small `go/internal/jobs/pending_actions.go` first; later `windows_updates.go` and `task_schedule.go`, job-specific tests. Use the current deployment scheduler for bounded invocations initially; a new distributed scheduler framework is not needed to migrate the first job.

**Required semantics:** Windows update scheduling uses agent-local date/hour, last-installed date, disable settings, online/version filtering and batches of 40 with pacing. Monthly source contains unusual month/day clamping: test it explicitly before correcting it. POSIX `scheduled_task_runner` checks daily/weekly/monthly/monthly-DOW/run-once/onboarding, uses TaskResult last_run/run_status/locked_at, and has a 55-second guard. It currently bulk-updates RUNNING and publishes inside a transaction; Go must claim/commit before remote send so callbacks do not race invisible state. A worker crash after publish must not imply safe re-execution.

**Model hooks:** AutomatedTask inherits BaseAuditModel, invalidates policy/agent task caches, and marks affected Windows TaskResult rows NOT_SYNCED when designated schedule fields change. Port these when enabling writes; read parity alone does not provide scheduling parity. Windows schedule create/modify/delete/run tasks and orphan cleanup are separate remote side effects. Task callbacks, collector results, email/SMS/Matrix alert production also remain dependencies.

**Tests:** fake clock across DST folds/gaps and month ends; two competing scheduler instances; crash before/after claim and publish; stale claims; repeated callbacks; disabled jobs; last-installed same-local-day suppression; scheduled task inheritance and resynchronization; worker restart without double execution. Use advisory locking or atomic conditional claims for the specific job; reuse mesh reconciliation's generation concept only for idempotent reconciliation work.

**Production cutover blockers:** do not stop Celery globally after these five slices. The beat inventory also includes Matrix dispatch, reports, self-updates, orphan tasks, outages, snooze expiry, maintenance, caches, scheduled-task sync, SNMP pruning, inventory digests, Mesh permissions and alert resolution. Inventory every `.delay()`/`.apply_async()` producer too. For each migrated job, disable its Django producer/beat entry before activating Go, retain rollback ownership instructions, and verify no queued old job can duplicate a side effect. No command worker can safely inherit MeshCentral's unconditional at-least-once retry policy.
