# Local staging DNS-01 hooks

Preparation only: adding these files changes no DNS records. The hook permits
only `api2.q-dt.de`, `rmm2.q-dt.de`, and `mesh2.q-dt.de`, in Hetzner zone
`1278188` (`q-dt.de`). It loads the existing DNS project's provider and `.env`.
Run from `/Users/jqueisser/Projekte/dns`; never copy tokens into command arguments.

Run one certbot process at a time. The provider replaces an entire TXT RRset
without compare-and-swap: concurrent external writers could otherwise lose a
change between read and write. Other existing TXT values and TTL are preserved;
cleanup removes only `CERTBOT_VALIDATION`, deleting an RRset only when empty.
Authorization polls every authoritative NS for up to 60 seconds after the API
write. A timeout fails issuance; cleanup can safely be repeated with the same
environment. API failures may require that cleanup after the problem is fixed.

After separate authorization to issue certificates, run from the DNS repo:

```sh
cd /Users/jqueisser/Projekte/dns
uv tool run --from certbot certbot certonly --manual --preferred-challenges dns \
  --manual-auth-hook '/Users/jqueisser/Projekte/dns/node_modules/.bin/tsx /Users/jqueisser/Projekte/tacticalrmm/api/go/deploy/staging/acme_dns_hook.mjs --action auth' \
  --manual-cleanup-hook '/Users/jqueisser/Projekte/dns/node_modules/.bin/tsx /Users/jqueisser/Projekte/tacticalrmm/api/go/deploy/staging/acme_dns_hook.mjs --action cleanup' \
  --config-dir /private/tmp/trmm-staging-acme/config \
  --work-dir /private/tmp/trmm-staging-acme/work \
  --logs-dir /private/tmp/trmm-staging-acme/logs \
  --cert-name api2.q-dt.de \
  -d api2.q-dt.de -d rmm2.q-dt.de -d mesh2.q-dt.de
```

Certbot prompts for account registration/email and terms if needed. Use
`--test-cert` first if an untrusted ACME staging certificate is sufficient;
omit it for a publicly trusted certificate. Neither mode needs inbound access
to the local LXC. The private key and full chain are written beneath
`/private/tmp/trmm-staging-acme/config/live/api2.q-dt.de/`; keep the private key
private. These hooks do not install certificates or modify any server.
