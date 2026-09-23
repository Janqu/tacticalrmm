// Local certbot hook. Run via the DNS project's tsx so its provider TS loads.
import { Resolver } from 'node:dns/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';

const zoneID = '1278188';
const zoneName = 'q-dt.de';
const domains = new Set(['api2.q-dt.de', 'rmm2.q-dt.de', 'mesh2.q-dt.de']);

export function challengeInput(argv, env) {
  if (argv.length !== 2 || argv[0] !== '--action' || !['auth', 'cleanup'].includes(argv[1])) {
    throw new Error('Expected --action auth or --action cleanup.');
  }
  if (!domains.has(env.CERTBOT_DOMAIN)) throw new Error('Domain is outside the staging allowlist.');
  if (!/^[A-Za-z0-9_-]{43,256}$/.test(env.CERTBOT_VALIDATION || '')) {
    throw new Error('Invalid DNS challenge value.');
  }
  return {
    action: argv[1],
    name: `_acme-challenge.${env.CERTBOT_DOMAIN.split('.')[0]}`,
    validation: env.CERTBOT_VALIDATION,
  };
}

// Preserve unrelated records, comments, and TTL. TXT API values use DNS quotes.
export function mergeRecords(records, validation, action) {
  const own = (record) => record.value === validation || record.value === JSON.stringify(validation);
  if (action === 'cleanup') return records.filter((record) => !own(record));
  if (records.some(own)) return records;
  return [...records, { value: JSON.stringify(validation), comment: 'Staging ACME DNS-01' }];
}

async function waitForAuthoritativeTXT(name, validation) {
  const resolvers = [];
  const resolver = () => {
    const instance = new Resolver({ timeout: 1500, tries: 1 });
    resolvers.push(instance);
    return instance;
  };
  let timer;
  let stopped = false;
  try {
    await Promise.race([
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          stopped = true;
          reject(new Error('Authoritative TXT propagation did not complete within 60 seconds.'));
        }, 60_000);
      }),
      (async () => {
        const recursive = resolver();
        const nameservers = await recursive.resolveNs(zoneName);
        if (!nameservers.length) throw new Error('No authoritative nameservers found.');
        const servers = await Promise.all(nameservers.map(async (ns) => {
          const addresses = await recursive.resolve4(ns);
          if (!addresses.length) throw new Error('Nameserver address lookup failed.');
          const direct = resolver();
          direct.setServers([addresses[0]]);
          return direct;
        }));
        while (!stopped) {
          const found = await Promise.all(servers.map(async (direct) => {
            try {
              const records = await direct.resolveTxt(`${name}.${zoneName}`);
              return records.some((parts) => parts.join('') === validation);
            } catch {
              return false; // NXDOMAIN or a transient propagation/timeout error.
            }
          }));
          if (found.every(Boolean)) return;
          if (!stopped) await delay(1500);
        }
      })(),
    ]);
  } finally {
    stopped = true;
    clearTimeout(timer);
    for (const instance of resolvers) instance.cancel();
  }
}

async function main() {
  const { action, name, validation } = challengeInput(process.argv.slice(2), process.env);
  // Import only after validating all inputs; dotenv loads from the DNS repo cwd.
  const { createProvider, loadAppConfig } = await import('/Users/jqueisser/Projekte/dns/src/providers/index.ts');
  const config = loadAppConfig({ provider: 'hetzner' });
  // Never send this account's credentials to an environment-selected endpoint.
  if (process.env.HDNS_BASE_URL && process.env.HDNS_BASE_URL !== 'https://api.hetzner.cloud/v1') {
    throw new Error('Nonstandard DNS API endpoint is not allowed.');
  }
  const provider = await createProvider(config);
  const zone = await provider.getZone(zoneID);
  if (zone.name !== zoneName || String(zone.id) !== zoneID) throw new Error('DNS zone identity mismatch.');
  const sets = await provider.listRRsets(zoneID);
  const existing = sets.find((set) => set.name === name && set.type === 'TXT');
  if (sets.some((set) => set.name === name && set.type === 'CNAME')) {
    throw new Error('Challenge name is delegated by CNAME; refusing to modify it.');
  }
  const previous = existing?.records ?? [];
  const records = mergeRecords(previous, validation, action);
  if (JSON.stringify(previous) !== JSON.stringify(records)) {
    if (existing && records.length === 0) {
      await provider.deleteRRset(zoneID, name, 'TXT');
    } else if (existing) {
      await provider.updateRRset(zoneID, name, 'TXT', { records, ttl: existing.ttl });
    } else if (records.length) {
      await provider.createRRset(zoneID, { name, type: 'TXT', ttl: 60, records });
    }
    await provider.flush?.(zoneID);
  }
  if (action === 'auth') await waitForAuthoritativeTXT(name, validation);
  // stdout is deliberately empty: certbot exposes auth stdout to cleanup.
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => {
    // Provider errors can contain request bodies; do not print them or tokens.
    console.error('Staging ACME DNS hook failed; inspect configuration or authoritative DNS. No secrets were logged.');
    process.exitCode = 1;
  });
}
