# QDT probe credential upgrade

This change replaces the shared SNMP API key with a dedicated credential bound
to one probe agent and its site. These credentials authenticate only the
`qdt_snmp/probe/<agent>/devices/` endpoint; they are not general RMM API keys.
Dashboard users, including administrators, use the regular masked SNMP endpoints.

## Deployment

1. Back up the database and confirm the deployed branch and commit.
2. Deploy this branch using the normal RMM update process, including Django
   migrations. Restart all Django/ASGI and Celery workers together so old code
   cannot continue accepting the revoked credential.
3. Migration 0004 creates credentials for existing managed QDT SNMP Poller tasks,
   changes their key argument to `{{agent.snmp_probe_key}}`, and revokes both the
   named `snmp-probe` API key and any API key stored as `global.snmp_api_key`.
   A reused administrator/integration key is also revoked: issue a separate key
   for that integration if necessary. Other global secrets are untouched.
4. Confirm that polling resumes at each site and the latest readings advance.
   Agents fetch task actions from the server when running. Already running polls
   with the old key will fail closed; the next run uses the scoped credential.
5. Custom scripts or separately scheduled pollers using the former global key
   must be reprovisioned using the site's existing probe setup action. If a site
   has multiple managed pollers, the migration designates the first by task ID;
   reprovision that site to select the intended agent.

The task definition stores only the template, not the key. The key is resolved
for the assigned agent at execution time. Moving an agent to another site
invalidates its old credential. Reprovisioning onto another agent rotates the
key, so the retired probe cannot keep polling.

The credential necessarily reaches the assigned probe process. It does not grant
access to another site, other agents or the general RMM API. As with other RMM
secrets, protect the database and the probe host.

The migration is intentionally irreversible and never recreates the shared key.
Do not roll back to code that uses the old probe authorization. Recover using a
forward fix or an explicitly reviewed restore and credential rotation.

## Reports

Customer health reports now require `can_list_agents` and restrict clients,
agents, alerts and totals to the user's client/site scope. A site-only role can
see only its sites within a permitted customer; foreign customers return 404.
