# Arbeitspaket Skriptausführung

Stand 22.09.2026: **Synchrone Remote-Ausführung und einfache Ergebnis-Callbacks sind innerhalb der unten genannten Grenzen implementiert und lokal getestet.** 74 Ausführungs- und 54 Callback-Vergleiche bestehen. Zusätzlich bestehen 49 Vergleiche für den expliziten Async-Modus `forget`; Der synchrone Notizmodus besteht 50 Vergleiche. Synchrone Collector sind mit 173 Vergleichstests implementiert; Collector-Callbacks sind mit 156 Vergleichstests implementiert; Neue markierte Notiz-Callbacks über `note_async` sind mit 24 Ablauf- und 14 Schema-Prüfungen implementiert. Server-, E-Mail- und kombinierte Collector-/Notizmodi bleiben offen; keine produktive Aktivierung. Grundlage: [MIGRATION_NEXT.md](MIGRATION_NEXT.md), Zuständigkeiten im [zentralen Board](MIGRATION_WORKSTREAMS.md).

## Vorhandene Bausteine und Grenzen

Implementierungsfortschritt: Der reine Transformationsteil von S1 ist jetzt
in `script_expansion.go` und `script_expansion_values.go` umgesetzt. Resolver
werden übergeben. Ein lesender DB-Resolver unterstützt inzwischen explizite
Agent-/Site-/Client-Skalarfelder, sichere Beziehungen, Custom Fields inklusive
Defaults und exakte globale Schlüssel. 181 DB-Vergleiche bestehen. Beliebige
Properties bleiben offen; fehlende oder doppelte
globale Schlüssel werden ohne Log-Schreibzugriff abgewiesen.
Bei unterstützter Ausführung werden Diagnose-Logs für leere Werte gemäß frisch
gelesener Logstufe innerhalb der Vorab-Transaktion geschrieben. Audit und Verlauf
werden vor dem Versand committed; frühe Ergebnis-Callbacks sind getestet.
394 Vergleiche mit den Python-Originalfunktionen und 17 explizite
Ablehnungsfälle bestehen. Python-spezifische Regex-Konstrukte und mehrdeutige
Werttypen werden abgewiesen. Für geordnete Objekte gibt es `ScriptObject`;
ungeordnete Go-Maps mit mehreren Schlüsseln werden nicht stillschweigend sortiert.
Die folgenden S1–S12-Pakete sind damit noch nicht als Ganzes abgeschlossen.

- [scripts_reads.go](internal/httpapi/scripts_reads.go), [scripts_writes.go](internal/httpapi/scripts_writes.go), [script_snippets.go](internal/httpapi/script_snippets.go): Speicherung/Projektion, keine Ausführung und kein Ersatz für Template-Auflösung.
- [agent_rawcmd.go](internal/httpapi/agent_rawcmd.go): Berechtigung/Scope, vor dem Versand committed History, Callback während der NATS-Anfrage, Audit-Fehler nach Remote-Ausführung. Dieses Muster übernehmen; keinen offenen DB-Lock während Remote-Ausführung halten.
- [agent_history_callback.go](internal/httpapi/agent_history_callback.go), [agent_tokens.go](internal/accounts/agent_tokens.go): DRF-Agenttoken und Bindung an Agent/History; einfache Skript-Histories werden unterstützt, Collector-Histories werden ebenfalls unterstützt; Task- und Note-Histories bleiben gesperrt.
- [audit.go](internal/audit/audit.go): JSON-AfterValue kann inzwischen auch ein String sein; Größenbegrenzung und Meldungskürzung wiederverwenden. Skript-Audit ist eine andere Sourcefunktion als Raw-Command-Audit.
- [agents_wmi.go](internal/httpapi/agents_wmi.go): Python-artige Wahrheitswerte/Stringdarstellung teilweise vorhanden; keine allgemeine Django-Attributauflösung. [custom_fields.go](internal/httpapi/custom_fields.go) verwaltet Definitionen, nicht den vollständigen Collector-Schreibpfad.
- [agentbus/client.go](internal/agentbus/client.go): Request/Reply und begrenztes Publish vorhanden. Bestehendes Reply-Limit 1 MiB und HTTP-Bodylimit 4 MiB begrenzen Skriptergebnisse. Django `TRMM_MAX_REQUEST_SIZE` ist standardmäßig 10 MiB. Kein stilles Anheben globaler Limits.

## Verifizierte Source-Verträge und offene Entscheidungen

### 1. Templates, Snippets und DB-Werte — zuerst, ohne Versand

Quellen: [Script.code/code_no_snippets/replace_with_snippets/parse_script_args/parse_script_env_vars](../tacticalrmm/scripts/models.py), [get_db_value/replace_arg_db_values/format_shell_array/format_shell_bool](../tacticalrmm/tacticalrmm/utils.py), [CustomField.default_value](../tacticalrmm/core/models.py), bestehende Fälle in [scripts/tests.py](../tacticalrmm/scripts/tests.py).

- `code` verwendet `script_body or ""`. Snippet-Muster `{{(.*)}}` ist **greedy und nicht mehrzeilig**. Namen werden getrimmt, fehlende Snippets bleiben unverändert; Ersetzungen sind nicht rekursiv. Das gesamte gefundene Snippet wird anschließend als Regex-Muster benutzt, nicht als escaped Literal; Backslashes im Ersatz werden verdoppelt. Regex-Metazeichen und mehrere Marker auf derselben Zeile gehören in die Referenzfälle.
- Args nutzen ebenfalls greedy Marker. Fehlgeschlagene/falsy Ersetzungen lassen das Argument unverändert. Ersatztexte durchlaufen Python-Regex-Ersatzsemantik mit `re.escape`-Fallback. Ein schlichtes `strings.ReplaceAll` wäre nicht automatisch äquivalent.
- Env-Variablen: Einträge ohne `=` werden übersprungen; geprüft wird nur `split("=")[1]`. Ohne Marker bleibt der Originaleintrag inklusive weiterer `=` erhalten. Bei erfolgreicher Ersetzung gehen zusätzliche Teile hinter dem zweiten `=` verloren; bei Marker mit falsy Ersatz verschwindet der gesamte Eintrag. Nicht unbeabsichtigt durch `SplitN` korrigieren.
- DB-Auflösung: `global.NAME` greift exakt auf GlobalKVStore zu. Zweiteilige Agent/Site/Client-Ausdrücke versuchen zunächst Custom Fields, erst dann Modellattribute. Leere Nicht-Checkbox-Werte fallen auf den Feld-Default zurück; Checkboxen werden zu bool. Relationsattribute und Properties werden durchlaufen, Callables abgelehnt. Fehlende Attribute überspringt die Source teilweise, statt zwingend abzubrechen; falsy Zwischenwerte liefern `None`. Das ist ein eigener Vertrag, keine SQL-Spaltenliste.
- Formatierung: Strings außer CMD-Args erhalten einfache Quotes; PowerShell verdoppelt Apostrophe auch bei `quotes=False`. Listen werden mit Kommas verbunden, Wörterbuchwerte per Python `json.dumps` ausgegeben; Bool ergibt `$True/$False` in PowerShell, sonst `1/0`. Fehlende Lookup-Werte erzeugen Scripting-DebugLogs, teils sowohl beim Global-Lookup als auch beim Wrapper. Auflösungswerte können Geheimnisse enthalten: Fehlerberichte/Testdiffs dürfen diese nicht ausgeben.

**Implementierungsschritt S1:** kleiner eigener Resolver mit expliziter Zuordnung unterstützter Relations-/Property-Zugriffe, danach Snippet-, Argument- und Env-Expansion. Keine dynamisch interpolierten SQL-Identifier und keine willkürliche Methodenaufruf-Emulation. Für nicht abbildbare Properties/Regex-Konstrukte vor Ausführung ausdrücklich fehlschlagen oder beim Django-Routing bleiben; fehlende Templates nicht pauschal als Erfolg behandeln. Sicherheitskorrekturen gegenüber den genannten Source-Eigenheiten separat dokumentieren.

**Tests:** Python-Referenz direkt auf obigen Funktionen; reale isolierte Agent/Site/Client/Global-/Custom-Field-Fixtures; mehrere/fehlende Marker, Regex-Sonderzeichen, Backslash-Rückreferenzen, leere Werte, 0/False, Listen/Dicts/Unicode, Apostrophe, CMD versus PowerShell versus weitere Shells, Env-Werte mit mehreren `=` und fehlende/duplizierte DB-Datensätze. Die Funktionstests müssen auch DebugLog-Seiteneffekte erfassen. Vorgesehene Dateien: `internal/httpapi/script_expansion.go`, Tests und `tools/compare_script_expansion.py`.

### 2. Ein synchrones gespeichertes Skript + vollständiger einfacher Skript-Callback

Quellen: [agents.views.run_script](../tacticalrmm/agents/views.py), [Agent.run_script/nats_cmd](../tacticalrmm/agents/models.py), [RunScriptPerms](../tacticalrmm/agents/permissions.py), [AuditLog.audit_script_run](../tacticalrmm/logs/models.py), [AgentHistoryResult.patch](../tacticalrmm/apiv3/views.py), [AgentHistorySerializer](../tacticalrmm/agents/serializers.py).

- Route POST `/agents/<agent_id>/runscript/`: `can_run_scripts` plus Scope. Eingaben `script`, `output`, `args`, `env_vars`, `timeout`, `run_as_user`, optional `run_on_server`. Source prüft hier weder `supported_platforms` noch eine Mindest-Agentversion. Request-Args werden verwendet, nicht stillschweigend die gespeicherten Script-Defaults.
- Source erstellt erst Skript-Audit, dann SCRIPT_RUN-History mit Script-FK und Username auf 50 Zeichen gekürzt. `Agent.run_script` erzwingt gespeichertes `run_as_user=True`, expandiert Args/Env/Code und sendet `runscript` oder bei `full=True` `runscriptfull`. Beide NATS- und Payload-Timeouts sind im View angefordert +3 Sekunden, **nicht zusätzlich nochmals +2**. Payload enthält History-`id`, `script_args`, `{code,shell}`, `env_vars`, `nushell_enable_config`, `deno_default_permissions`. Letztere stammen aus Deployment-Settings, nicht aus einer erfundenen Go-Voreinstellung.
- Zunächst ausschließlich `output="wait"`, `run_on_server=False`: andere Modi vor Side Effects ablehnen/routen. Source gibt den Reply unverändert zurück, auch `"timeout"`; gewünschte Go-Transportfehlerabbildung ist als Abweichung festzulegen. Audit/History/Expansion-Reihenfolge ist zu testen; Vorvalidierung vor Source-Audit wäre eine bewusste Sicherheitsänderung.
- Callback PATCH `/api/v3/<pk>/<agentid>/histresult/`: Source nutzt DRF-Token und History-Agent, ignoriert aber URL-Agent und lässt via `fields="__all__"` wesentlich mehr Felder schreiben. Go muss die bestehende URL-/History-Bindung und Eigentümerschaft bewahren; Resultat-Felder zulassen, keine Agent-/Script-/Collector-Umlenkung durch Callback.
- Bei Content-Length über `TRMM_MAX_REQUEST_SIZE` setzt Source `script_results.stdout=""`, `stderr="Content truncated due to excessive request size."`, `retcode=1`, andere Ergebnisfelder bleiben. Source parst dabei dennoch den Request. Go benötigt vor Cutover eine ausdrücklich begrenzte Ingest-/Truncation-Regel für normale, übergroße und chunked Requests; 4-MiB-Abweisung ist nicht diese Source-Semantik. Gelöschte Script-FK und wiederholte Resultate müssen berücksichtigt werden.

**Schritt S2:** einfacher Skript-Callback ohne Collector/Note, dann synchroner Handler gemeinsam aktivieren. Neue Handlerdatei `agent_script_execution.go`; Callback nur eng erweitern. S1 muss vorher abgeschlossen sein. Config-Werte und maximale Laufzeit/Reply-Größe einschließlich Proxybudget festlegen. Audit und History vor Versand committen; keine automatische Wiederholung nach Timeout oder DB-Fehler nach Remote-Ack.

**Tests:** alle ScriptShell-Werte und Config-Payloads, fehlendes Skript, Scope/Installer/Token-Trennung, Script-run-as-user-Override, sofortiger echter lokaler HTTP-Callback vor Reply, unveränderte Execution-ID, volle/nulle/gelöschte Script-FK, UTF-8 und Truncation-Grenzen, Redelivery, Rollback vor Versand und Ergebnis-/Audit-DB-Fehler danach. Keine echten Agenten.

### 3. Asynchron, Collector, Note, E-Mail — getrennte Freigaben

Quellen: [run_script](../tacticalrmm/agents/views.py), [Agent.run_script/nats_cmd](../tacticalrmm/agents/models.py), [run_script_email_results_task](../tacticalrmm/agents/tasks.py), [AgentHistoryResult.patch](../tacticalrmm/apiv3/views.py), `CustomField.get_or_create_field_value`, `AgentCustomField/ClientCustomField/SiteCustomField.save_to_field`, `Note`.

| Schritt | Umsetzung und Abhängigkeiten | Abnahmetests |
|---|---|---|
| S3 einfacher Async-Modus | Nach S1/S2 und Transport-Publish: Source `wait=False` publiziert, flusht und schließt; View meldet `<script> will now be run on <hostname>`. Brokerannahme ist kein Ausführungserfolg. Keine Request-überlebende ungesicherte Goroutine und kein automatisches Resend. | Publish/Flush-Abbruch, kein Subscriber, Shutdown, Callback vor Response, genau eine Nachricht, History bleibt bei unklarer Zustellung sichtbar. |
| S4 synchroner Collector und Note | Collector nutzt einfachen synchronen `runscript`-String, `strip()` oder letzte getrimmte Zeile; Ziel Agent/Client/Site aus Field-Modell. `save_to_field`: Text/Number/Single/Datetime in string_value, Multiple `split(',')`, Checkbox Python-Truthiness (String `false` ist wahr). Note speichert ganzen Reply mit auslösendem Benutzer. Field-Ziel vor Execution validieren ist eine geplante Abweichung zur späten Source-Prüfung. | Alle Feldtypen/Defaults, 0/False/Leerzeilen/Kommas, Ziel-Scope, Ausgabe mit Fehlertext, Note-Autor, Unique-Rennen bei get_or_create, DB-Fehler nach Ausführung. |
| S5 Callback-Collector/Note | Andere Variante: History-Felder `custom_field`, `collector_all_output`, `save_to_agent_note`; Quelle ist `script_results.stdout`, Note-Autor ist Agenttoken-Benutzer. Source speichert History vor weiteren Writes und erstellt bei jeder Wiederholung eine neue Note. Benötigt Transaktion für lokale Writes und per-History Abschlussmarker/Resultatidentität für replay-sichere Notes; einfaches „Ergebnis existiert“ reicht bei veränderter Redelivery nicht ohne definierte Policy. | Wiederholung/gleichzeitige Callbackzustellung, kein doppelter Note-Eintrag, getrennte Collector/Note-Fehler, gelöschtes Custom Field, Agent-/Site-/Client-Bindung. |
| S6 E-Mail | Celery-Aufruf führt `full=True`, `wait=True` aus; Timeout erzeugt Scripting-DebugLog ohne Mail. Betreff enthält Client/Site/Hostname/Script; Ausführungszeit vier Nachkommastellen. Explizite Empfänger oder Core-Standard; SMTP mit optional Auth/STARTTLS, Fehler werden geloggt. Ausführung und Mailzustellung getrennt dauerhaft verfolgen, SMTP-Retry darf Skript nicht erneut starten. | Fake SMTP/NATS, default/explizite Empfänger, Auth/TLS, Resultat-Schema, SMTP-Abbruch vor/nach Annahme, Worker-Neustart, keine doppelte Ausführung. |

### 4. Server-Ausführung und weitere Skript-Produzenten

**S7 Server-Ausführung:** [core.utils.run_server_script](../tacticalrmm/core/utils.py), `CoreSettings.server_scripts_enabled`, `RunServerScriptPerms`, `agents.views.run_script` und `core.views.TestRunServerScript` separat migrieren. Flags `HOSTED`, `TRMM_DISABLE_SERVER_SCRIPTS`, `DEMO` sowie DB-Schalter beachten. Source expandiert Snippets, parst Args/Env im View mit Agent und nochmals im Runner ohne Agent, übernimmt Server-Environment, normalisiert CRLF, erstellt ausführbare Tempdatei und startet diese **direkt**, nicht automatisch einen Interpreter anhand `shell`; Shebang ist relevant. Timeout gibt 98, sonstige Prozessfehler 99; Tempdatei wird entfernt. View speichert `script_results` mit History-ID, liefert ohne ID und `execution_time` als vierstelligen String. Prozessgruppe/Abbruch, Runtime/Arbeitsverzeichnis, Secret-Environment, Parallelität und Ausgabelimit müssen vor Go-Freigabe explizit entschieden werden. Tests nur mit harmlosen lokalen Fixtureprozessen; Servermodus bleibt bis dahin Django/disabled.

| Offenes Folgepaket | Exakte Quellen / Abgrenzung | Zuständigkeit |
|---|---|---|
| S8 Testskript | `scripts.views.TestScript.post`, `/scripts/<agent>/test/`: ungespeicherter Code, `runscriptfull`, keine History-ID, kein +3-Offset, Audit nach Reply mit Request/Ergebnis. Keine reine Preview; führt Code aus. | Skript-Workstream nach S1/S2; Audit-Datenprojektion/Größenlimits separat testen. |
| S9 Bulk-Skript | `agents.views.bulk`, `scripts.tasks.bulk_script_task`, `tacticalrmm.nats_utils.abulk_nats_command`: Zielauswahl/Scope, eine History je Agent, `runscriptfull`, individuelle Expansion, Collector-/Note-Flags, Bulk-Audit und Celery-Produzent. | Skript-Workstream; Publish und S5 sowie dauerhaft unterscheidbare Ausführungsidentitäten erforderlich. Keine Mesh-Singleton-Coalescing-Queue. |
| S10 Check-/Task-Ausführung | `checks.serializers.CheckRunnerGetSerializer`, `scripts.serializers.ScriptCheckSerializer`, `autotasks.serializers.TaskGOGetSerializer`: liefern expandierten Code/Args/Env. Task-Serialisierung entfernt gelöschte Script-Actions und speichert das Task-Modell einschließlich Hooks. | Skript-Workstream liefert Resolver/Payload-Bausteine; Scheduler-Workstream besitzt Claim/Timing/TaskResult; Check-/Task-Mutationspaket besitzt Modellhooks. Read-CRUD deckt das nicht ab. |
| S11 Alert-Skripte | `Alert.handle_alert_failure`, `handle_alert_resolve`, `parse_script_args`; abweichender Regex-/Quote-Parser, `run_on_any=True`, Ping-Fallback auf andere Online-Agenten, `full=True`, Aktions-History/Flags, Server-/REST-Zweig. Failure- und Resolve-Env-Expansion unterscheiden sich. | Skript-/späteres Alert-Mutationspaket gemeinsam mit Scheduler/Alert-Produzenten. Agent-Fallback ist neue Ausführungsautorisierung; kein Nebenprodukt von Einzelagent-Support. |
| S12 Resultat-Lebenszyklus | `agents.views.ScriptRunHistory`, `agents.tasks.prune_agent_history`, gelöschte Script-/CustomField-FK, bereits eingeplante Celery-Ausführungen und noch verspätete Callbacks. | Scheduler besitzt Pruning/Produktionsumschaltung; Skript-Workstream dokumentiert zulässige verspätete Resultate und Tombstone/Replay-Entscheidungen. |

Der oben ausgewiesene S1/S2-Teilumfang ist lokal getestet; produktiver Cutover bleibt separat. S3–S6 werden jeweils eigenständig implementiert und geprüft. S7–S12 dürfen parallel geplant werden, aber keine unvollständige Route von Django übernehmen. Scheduler-Arbeit bleibt eine externe Abhängigkeit, keine implizit mitgelieferte Funktion.

## Größte Risiken und spätere Zuständigkeiten

1. Template-Expansion kann Geheimnisse auflösen und Source-Properties mit Nebenwirkungen erreichen. Ein vereinfachter Resolver kann falsche Befehle ausführen; ein zu allgemeiner Resolver kann Berechtigungen überschreiten.
2. Timeout/Flush-Fehler beweisen keine Nichtausführung. History/Audit vor Versand, keine unkontrollierten Wiederholungen; DB-Rollback kann eine Remote-Ausführung nicht rückgängig machen.
3. Skript-Callback ist mehr als JSON-Ablage: Größenlimit, frei beschreibbare Source-FKs, Collector-Typkonvertierung und doppelte Notes müssen vor Routing entschieden werden.
4. E-Mail und Serverprozesse benötigen eigene Lebenszyklen. Der bestehende Mesh-Outbox-Retry ist hierfür ungeeignet; keine Zusage „genau einmal“ ohne passende Agent-/Job-Identität.

Zusätzliche spätere Zuständigkeit dieses Workstreams laut Root: **Accounts/SSO, übrige Core-API, Check-/Task-/Automation- und Alert-Template-Mutationen**. Sie werden im zentralen Board geführt; dieser Analyseauftrag implementiert und plant deren vollständige Migration nicht zusätzlich. Bei S7/S10/S11 sind nur die konkreten Skript-Schnittstellen zu diesen Paketen zugeordnet.

Aktueller S4-Teilfortschritt: `output="note"` speichert Text unverändert mit dem
auslösenden Benutzer, null als SQL NULL. Andere Antworttypen und NUL werden
bewusst mit 502 abgewiesen. Transportfehler erzeugen keine Notiz. Fehler beim
Speichern nach Ausführung behalten Audit/History; kein erneuter Versand.
Synchrone Collector, Collector-Callbacks und neue markierte Notiz-Callbacks sind umgesetzt; unmarkierte Notiz-Altbestände bleiben ausgeschlossen.

S4 Collector: Vorprüfung von Feld, Typ und Ziel vor dem Versand; nach der Antwort
erneute Prüfung unter Sperren, einschließlich Standort- und Kundenzuordnung.
Geänderte Ziele/Definitionen liefern 409, gelöschte Felder 404. Nur Textantworten
werden verarbeitet (sonst 502), Transportfehler schreiben keine Feldwerte.
Fünf Sekunden Sperrwartezeit begrenzen lokale Konflikte; kein Wiederholungsversand.
Go-Schreibzugriffe sind serialisiert. Parallele Django-Schreiber beachten diese
Sperrfolge nicht; Standort-/Kundenwerte haben dort keinen Unique-Constraint.
Bestehende Duplikate werden deshalb vor dem Versand abgewiesen.

### Notiz-Callbacks: implementierter Ablauf

Go startet ohne automatische Schemaänderungen. Eine explizite SQL-Migration
analog `migrations/001_mesh_sync.sql` muss vor Aktivierung eine kleine
Abschlusstabelle bereitstellen: History-ID als Primärschlüssel/Fremdschlüssel
mit ON DELETE CASCADE, ursprüngliche Agent-ID, nullable JSONB-Payloadidentität
und nullable Notiz-ID mit ON DELETE SET NULL. Gelöschte Notizen dürfen die
Abschlusskennung nicht löschen, sonst würde ein Replay die Notiz wieder anlegen.

Der Producer legt die zunächst leere Kennung mit jeder neuen Go-Notiz-History
in derselben Transaktion an. Alte Histories ohne Kennung bleiben abgewiesen;
eine nachträgliche Zuordnung anhand von Notiztext oder Zeit ist nicht zuverlässig.
Der Callback sperrt History und Kennung, prüft Agent/URL und verarbeitet History,
Notiz und Abschluss gemeinsam. Identischer validierter JSONB-Payload liefert
200 ohne Änderung, abweichender Payload 409. Die Identität umfasst alle erlaubten
Ergebnisfelder, nicht nur stdout. JSONB-Vergleich vermeidet eine zusätzliche
Hash-/Kanonisierungsimplementierung. Eine fehlende Payloadidentität bedeutet
pending, eine vorhandene bleibt auch nach Löschung der Notiz completed.

Schema und Producer sind mit expliziter Migration 002 und dem neuen Go-Modus
`note_async` implementiert. Nur neu angelegte, markierte Histories werden
verarbeitet; unmarkierte Altbestände und kombinierte Collector-/Notizfälle
bleiben 501. Keine produktive Migration oder Aktivierung.

Collector-Callbacks speichern stdout gemäß der gespeicherten Field-Verknüpfung
und collector_all_output. Verlauf und Feldwert werden gemeinsam committed;
Typfehler oder SQL-Fehler lassen beide unverändert. Wiederholungen wenden den
Wert erneut an (wie Django) und können spätere manuelle Feldänderungen überschreiben.
Es entstehen keine zusätzlichen Wertzeilen. Eine schon vor dem Callback gelöschte
Field-FK wird wie in Django als einfacher Verlauf behandelt; eine Feldänderung
während der Sperrübernahme wird abgewiesen. Unmarkierte Notiz- und Task-Histories bleiben 501.
