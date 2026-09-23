# Arbeitspaket: NATS Publish und Windows-Updates

Stand: 22.09.2026. **Umsetzungsplan mit dem unten ausgewiesenen Teilfortschritt.** Neue Dateien in offenen Schritten sind vorgeschlagene Ziele; bestehende Dateien werden ausdrücklich als solche bezeichnet. Pfade beziehen sich auf `api/`.

Fortschritt: **Schritt 1 (Publish-Transport) ist implementiert und getestet**,
einschließlich Race-Tests, simulierten Abbrüchen und lokalem NATS-Broker.
Auch Schritte 2–3 (Bereinigung, Scan und Scan-/Superseded-Callbacks) sind jetzt
implementiert: 26 Bereinigungs- und 93 Scan-/Callback-Vergleiche bestehen.
Die Helper aus Schritt 4 (wirksame Policy/Freigabe) sind mit 42 Vergleichen
implementiert. Schritt 5 (manuelle Installation) ist für den Startpfad umgesetzt
(128 Scan-/Install-/Callback-Vergleiche); PATCH-Einzelresultate und PUT ohne
Neustart bleiben wie zuvor. Bei neustartpflichtiger Policy bleibt PUT 501.
Die periodische Auto-Freigabe (`auto-approve-win-updates`) ist als One-Shot-Job
mit 12 Vergleichen umgesetzt; geplante Installation bleibt offen. Die Go-Routen
sind registriert; produktives Routing und Produktionstimer wurden nicht geändert.

Root übernimmt Integration und Routing. Dieses Arbeitspaket liefert Transport und manuelle Windows-Update-Ausführung. Script-Ausführung und Scheduler bleiben getrennte Arbeitspakete. Der Scheduler darf erst auf die hier geprüften Funktionen aufsetzen. Bis zur vollständigen Freigabe bleiben die betreffenden Django-Routen und Callback-Routen gemeinsam aktiv.

## Bestehende Bausteine

| Vorhanden | Wiederverwendung und Grenze |
| --- | --- |
| `go/internal/agentbus/client.go` | `Client.Request`, `Client.Publish`, `literalSubject`, MessagePack-Handle und begrenzter, kontextgebundener Verbindungsaufbau. Keine zweite Transportimplementierung anlegen. |
| `go/internal/httpapi/winupdates.go` | Lesen und Ändern gespeicherter Updates einschließlich Feldparsern. Kein Scan, Installieren oder Agent-Callback. Parser gezielt wiederverwenden; Callback darf nicht beliebige Verwaltungsfelder übernehmen. |
| `patchpolicy_writes.go`, `patchpolicy_reset.go` | Policy-CRUD/Reset und `patchPolicyProjection`; keine Berechnung der wirksamen Patch-Policy. |
| `agent_policies.go:resolveAgentPolicies` | Aktive/vererbte Policies mit Ausschlüssen und Blockierung frisch aus der DB bestimmen. Reihenfolge für Patch-Policy mit Django abgleichen. Keine Python-Pickle-Caches portieren. |
| `agent_callbacks.go:authenticateAgentCallback` | DRF-Agent-Token statt Knox-/API-Schlüssel; an gebundenen Agenten knüpfen. Update-Callbacks haben keine Agent-ID im URL: Eigentümer ausschließlich aus dem Token bestimmen. |
| `patchpolicy_writes.go:hasPermOnAgentPK` und vorhandene Agent-Berechtigungshelfer | Verwaltungsrouten benötigen `can_manage_winupdates` und Agent-Scope. Nicht mit Callback-Authentifizierung vermischen. |
| `go/internal/mesh/jobs.go`, `go/migrations/001_mesh_sync.sql` | Transaktionales Enqueue und generationssichere Quittierung als Beispiel für abgleichbare Zustände. Singleton und automatische Wiederholungen **nicht** für einzelne Installationen/Reboots verwenden. |

## 1. Publish als begrenzte Transportfunktion

**Quelle:** `tacticalrmm/agents/models.py:Agent.nats_cmd`, Zweig `wait=False`: verbinden, `msgpack.dumps(data)`, `publish(agent_id, ...)`, `flush`, schließen. Ein erfolgreicher Flush bestätigt den Broker, nicht die Ausführung und nicht einmal einen vorhandenen Subscriber. Der bisherige Django-Verbindungsfehler liefert `natsdown`; manche Aufrufer ignorieren ihn.

**Umsetzung:** `Client.Publish(ctx, subject, payload, timeout) error` in bestehender `go/internal/agentbus/client.go`; gemeinsamen Verbindungs-/Kodierungsablauf nur so weit extrahieren, wie Request und Publish ihn tatsächlich teilen. Drei Sekunden Verbindungsgrenze, begrenzter Flush, sichere TLS-Voreinstellung, keine Wiederverbindung und kein automatischer zweiter Publish. Parent-Cancellation beachten, Deadline-Fehler konsistent normalisieren und keine Tokens/Payloads protokollieren.

Der Aufrufer muss erkennen können, ob ein Fehler vor dem Sendeschritt liegt oder die Zustellung unklar ist. Kleiner Fehler-Wrapper mit Zustellphase genügt; keine allgemeine Queue-Abstraktion. Ein Abbruch während Flush ist kein Beweis, dass nichts gesendet wurde. Bereits gespeicherte Ausführungsdaten nicht deswegen löschen. Vorübergehende Fehler nicht automatisch erneut senden.

**Tests:** bestehende Fake-NATS-Peer-Tests erweitern: binäre Python-kompatible Payload, genau ein Publish, Flush/PING-PONG, kein Subscriber, falsches Subject, fehlende Konfiguration, Connect-Timeout, Cancellation, Abbruch nach Empfang vor Flush-Quittierung. Request-Regressionstests und Race-Test erneut laufen lassen. Lokaler Broker mit Python-Subscriber prüft den echten MessagePack-Vertrag. Keine realen Agents.

**Abnahme:** Transport allein zuerst integrieren; noch keine neue Produktionsroute. Broker-/Proxy-Limits und Fehlermeldungen dokumentieren. Ein erfolgreicher Publish darf im Produkt nicht als „Installation abgeschlossen“ dargestellt werden.

## 2. Supersedence als gemeinsame DB-Funktion

Dieser Schritt muss vor dem vollständigen Scan-Routing fertig sein, weil Scan-Start und Scan-Ergebnis beide aufräumen.

**Quellen:** `agents/models.py:Agent.delete_superseded_updates` und `apiv3/views.py:SupersededWinUpdate.post`. Zweite Route: POST `/api/v3/superseded/`, Body `guid`, Agent aus DRF-Token, alle passenden GUID-Zeilen dieses Agenten löschen, Antwort `"ok"`.

Die automatische Bereinigung gruppiert doppelte KBs, extrahiert Titelversionen aus `(Version ...)` beziehungsweise `(Versão ...)` ohne Beachtung der Großschreibung und sortiert nach PEP 440: Der Quellname `LooseVersion` ist ein Alias für `packaging.version.Version`, nicht die distutils-Klasse. Nicht parsebare Gruppen bleiben erhalten. Für ältere Versionen nimmt Django die erste passende Titelzeile mit `title__contains=version`; die gesamte Methode unterdrückt Fehler. Es gibt keine GUID-Eindeutigkeit im Modell.

**Umsetzung:** gezielter Helfer, etwa `go/internal/httpapi/winupdate_policy.go` oder eigene `winupdate_supersedence.go`, der im übergebenen DB-Kontext arbeitet; keine Transaktion intern öffnen, wenn der Aufrufer bereits eine besitzt. Superseded-Callback in `winupdate_callbacks.go` mit Token-Agent-Bindung. Nicht vorschnell durch SemVer oder „größte revision_number gewinnt“ ersetzen.

**Tests:** doppelte KBs/GUIDs, mehrere passende Titel, mehrteilige Zahlen, Versionspräfix-Kollisionen, portugiesischer Marker, ungültige/null Titel, installierte ältere Zeilen, kein Ergebnis und fremder Agent. Aus Django abgeleitete Fixture-Liste für `LooseVersion` festhalten. DB-Fehler bewusst sichtbar machen statt stiller Teilbereinigung; diese Sicherheitsabweichung getrennt testen.

**Abnahme:** Löschmenge gegen Django vergleichen, Transaktions-Rollback bei SQL-Fehler prüfen; keine Migration bestehender Daten als Nebenwirkung der Tests.

## 3. Scan plus vollständiger Scan-Callback

**Quellen:** `winupdate/views.py:ScanWindowsUpdates.post`, `winupdate/permissions.py:AgentWinUpdatePerms`, `winupdate/urls.py`; `apiv3/views.py:WinUpdates.post`, `apiv3/urls.py`; `winupdate/models.py:WinUpdate`.

**Verwaltungsroute:** POST `/winupdate/<agent_id>/scan/`. Berechtigung/Scope und Windows-Plattform vor Änderungen prüfen. Supersedence bereinigen, Commit, `{"func":"getwinupdates"}` publizieren. Antwort bei angenommener Zustellung: `A Windows update scan will be performed on <hostname>`. Ein DB-Fehler vor Commit darf keinen Publish auslösen. Ein Publish-Fehler kann eine bereits erfolgte Bereinigung nicht zurückrollen; nicht als Erfolg beantworten.

**Callback:** POST `/api/v3/winupdates/`, `wua_updates` als Liste. Django lehnt eine leere Liste mit `Empty payload` ab. Für vorhandene GUIDs wird die höchste ID ausgewählt und nur `downloaded`/`installed` geändert. Für neue Zeilen entsteht KB aus `"KB" + kb_article_ids[0]`; fehlende KB-Information überspringt die neue Zeile. Weitere neue Felder: GUID, Titel, Beschreibung, Severity, Kategorien/IDs, KB-IDs, URLs, Revision. Alle zurückgelieferten GUIDs zählen vor diesem Skip für die anschließende Bereinigung. Nicht zurückgelieferte, uninstallierte Zeilen löschen; installierte Zeilen behalten. Danach Supersedence bereinigen. Antwort `"ok"`.

**Modelldetails:** WinUpdate ist kein BaseAuditModel: keine automatischen Audit-/Modified-Felder oder Save-Signale. Neue Defaults: `action="nothing"`, `result="n/a"`, `date_installed=null`, Booleans false, Arrayfelder leere Listen. `support_url` und Elemente von `more_info_urls` sind unbegrenzte Textfelder; andere Arrayelemente maximal 255 Zeichen. SQL-NULL und JSON-/Array-Null nicht verwechseln.

**Umsetzung:** neue `go/internal/httpapi/winupdate_commands.go`, `winupdate_callbacks.go` mit einem gemeinsamen Transaktions-/Validierungsablauf, dazu `go/tools/compare_winupdate_execution.py`. Den vollständigen Callback vor dem ersten Go-Scan freigeben. Gesamtes Scan-Payload vor mutationswirksamer Verarbeitung validieren, anschließend kurze Transaktion mit Agent-Lock für konkurrierende Go-Callbacks. Bestehende Django-Schreibpfade nehmen diesen Lock nicht: gemischte Autoren bleiben ein gesondertes Cutover-Risiko.

**Tests:** Subscriber liefert sofort echten HTTP-Callback vor Flush/Antwort; vollständige Payload und Token-Bindung; neue/alte/fehlende KBs; höchste ID bei Duplikaten; stale deletion; unveränderte Actions/Metadaten bestehender Updates; Array-/Längenlimits; malformed letzter Listeneintrag rollt alles zurück; keine Audit- oder Celery-Aufrufe. Scan-Start ohne Berechtigung, auf POSIX und bei Brokerfehlern separat testen.

## 4. Wirksame Policy und Auto-Approval

**Quellen:** `agents/models.py:Agent.get_patch_policy`, `approve_updates`, `get_approved_update_guids`; `winupdate/models.py:WinUpdatePolicy`; `logs/models.py:BaseAuditModel`; `automation.models.Policy` und `Agent.get_agent_policies` für Prioritäten.

`get_patch_policy` nimmt die erste Agent-Policy-Zeile und erstellt sie bei Fehlen mit Modell-Defaults. Dann gewinnt die erste aktive vererbte Policy mit Patch-Policy. Nicht-`inherit`-Werte des Agenten überschreiben Critical/Important/Moderate/Low/Other. Frequenz-Override übernimmt Frequenz, Stunde und Wochentage; der Quellcode kopiert dabei **nicht** `run_time_day`. Reboot-Override und `reprocess_failed_inherit=false` übernehmen die entsprechenden Reprocess-/E-Mail-Werte. Die zusammengeführte vererbte Policy wird nicht gespeichert.

`approve_updates` setzt bei uninstallierten Updates passender Severity Action auf `approve`, auch wenn bisher `ignore` oder `nothing` gesetzt war. Severity `Other` entspricht leerem String, nicht automatisch NULL. GUID-Auswahl: alle `action=approve AND installed=false`, keine automatische Deduplizierung und keine Reprocess-Logik in dieser Methode.

**Umsetzung:** denselben frischen Policy-Resolver wie die vorhandenen Check-/Task-Lesewege verwenden, darauf kleines Patch-Overlay aufsetzen. Fehlende Agent-Policy in derselben kurzen Transaktion erstellen; Audit-Metadaten/explicit Audit bei authentifizierten Verwaltungsaufrufen nach vorhandenen Patch-Policy-Helfern erhalten. Agent-Callback hat keinen automatisch zu unterstellenden Benutzer-Auditkontext. Dokumentieren, dass frische DB-Auswertung von warmen Django-Policy-Caches abweicht.

**Tests:** Agent/Site/Client/Default, aktive/inaktive/ausgeschlossene/blockierte Policies, doppelte Patch-Policy-Zeilen und First-ID, sämtliche Inherit-Overrides, leer/NULL Severity, bereits ignorierte/approvte/installierte Updates. Fehlende Agent-Policy inklusive Defaults/Audit; keine Mutation der vererbten Policy; Rollback bei Approval-Fehler. Scheduler-Team erhält die getesteten Helfer, baut keinen eigenen Resolver.

## 5. Installieren und Erfolg-/Fehler-/Reboot-Callbacks

**Quellen:** `winupdate/views.py:InstallWindowsUpdates.post`; `apiv3/views.py:WinUpdates.patch/put`; `logs/models.py:DebugLog.info`; Policy-Helfer aus Schritt 4.

**Start:** POST `/winupdate/<agent_id>/install/`. Scope prüfen; Windows-Plattform explizit schützen (Django-Installroute lässt diesen Guard aus). Bereinigen, auto-approven, GUIDs bestimmen, Commit, dann `{"func":"installwinupdates","guids":[...]}` publizieren. Antwort `Approved patches will now be installed on <hostname>`. Kein impliziter zweiter Installationsversuch bei verlorener Antwort. Die manuelle Quellroute setzt `patches_last_installed` nicht; der Scheduler tut dies separat.

**Einzelresultat:** PATCH `/api/v3/winupdates/`, Body `guid`, `success`. Höchste ID dieses Agents/GUIDs wählen. Erfolg setzt `result=success`, `downloaded=true`, `installed=true`, `date_installed=now`; Fehler setzt nur `result=failed`. Danach Supersedence, Antwort `"ok"`. Quelle wirft bei fehlender GUID eine Exception; Go sollte vorhersehbar 404 liefern. Wiederholter Erfolg setzt in Django den Zeitstempel erneut: Parität gegen bewusst gewünschte Idempotenz abwägen und dokumentieren.

**Abschluss:** PUT `/api/v3/winupdates/`, Body `needs_reboot`. Agent speichern, wirksame Reboot-Policy bestimmen. `always` oder `required` mit gesetztem Flag publiziert `rebootnow` und schreibt bedingten DebugLog; anschließend Supersedence und `"ok"`. Dieser Callback hat eine Remote-Nebenwirkung. Datenbanktransaktionen dürfen während Reboot-Publish nicht offen bleiben.

**Zentrale Freigabesperre:** Der bestehende Abschlussvertrag besitzt keine Installations-/Callback-ID. Ein wiederholtes PUT kann einen zweiten Reboot auslösen; `always` lässt sich nicht allein über `needs_reboot` zuverlässig deduplizieren. Vor Routing des reboot-pflichtigen Abschlusszweigs entweder Agent-Protokoll um stabile Ausführungs-ID erweitern und diese eindeutig quittieren oder eine ausdrücklich begrenzte Betriebsstrategie beschließen. Nicht stillschweigend Exactly-once versprechen. Der Installations-Start und der Abschluss ohne Neustart sind freigegeben; der Neustart-Abschluss bleibt bis dahin bei Django.

**Tests:** exakte Payload, fehlende/leere GUID-Menge, Approval-Rollback, immediate callback, failed/success Duplikate, anderer Token-Agent, SQL-Fehler nach Remote-Ack, alle Reboot-Modi, wiederholte Abschlussmeldung, verlorener Flush und DebugLog-Level. Nachweisen, dass Rückmeldungen keine fremden Agent-/Policy-FKs ändern können und keine automatischen Publish-Retries stattfinden. Install-Start: Scope, POSIX-Ablehnung, Auto-Approval, null/doppelte GUIDs, Commit vor Publish und bekannte/unklare Zustellfehler.

## Integration und Übergabe

1. Transporttests und bestehende Request-Tests gemeinsam grün; Root übernimmt Registrierung erst nach Freeze.
2. Supersedence und Scan-Callback-Verträge im isolierten Schema gegen Django prüfen. Beide Autoren während Cutover koordinieren; Agent-Lock allein schützt nicht gegen weiterlaufendes Django.
3. Policy-/Approval-Tests abschließen; Helfersignaturen mit Scheduler-Team teilen. Die periodischen Funktionen `winupdate.tasks.auto_approve_updates_task`, `check_agent_update_schedule_task`, `bulk_install_updates_task` und `bulk_check_for_updates_task` bleiben bis zu deren separater Migration auf Celery.
4. Installations-/Reboot-Zustell- und Wiederholungssemantik entscheiden, dann Install-/Resultat-Routen gemeinsam freigeben. Kein globaler Celery-Stopp aufgrund dieses Arbeitspakets.
5. Produktionsnachweis: kontrollierter einzelner Test-Agent, Token-Callback-Endpunkte und Proxy-Timeouts korrekt geroutet, minimale Brokerrechte, nachvollziehbare unbekannte Zustellzustände, Rollback mit eindeutigem Scheduler-/Callback-Eigentümer. Während Analyse/Implementierung ausschließlich Fake-Peers und den isolierten lokalen Test-Broker benutzen.
