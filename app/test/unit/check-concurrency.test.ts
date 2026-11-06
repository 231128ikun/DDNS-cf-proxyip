import { describe, expect, it } from 'vitest';
import { ApiClient } from '../../web/src/api/client';
import { createHttpApp } from '../../src/transport/http';
import { CheckProxy } from '../../src/application/check-proxy';
import { CheckTarget } from '../../src/application/check-target';
import { MaintainManagedTarget } from '../../src/application/maintain-managed-target';
import { ResolveTarget } from '../../src/application/resolve-target';
import { normalizeManagedTarget } from '../../src/domain/managed-target';
import { alive } from '../../src/domain/probe-result';
import type { ProbeAdapter } from '../../src/ports/probe';
import type { DnsRepository } from '../../src/ports/dns-repository';

const addresses = Array.from({ length: 40 }, (_, index) => `203.0.113.${index + 1}`);

describe.each(['pool', 'domain', 'maintenance'] as const)('shared check concurrency: %s', (kind) => {
  it.each([[undefined, 8], [24, 24], [2, 2], [0, 1], [999, 40], [Number.NaN, 8]])(
    'uses %s without a separate backend cap (peak %s)', async (concurrency, expectedPeak) => {
      let active = 0;
      let peak = 0;
      let completed = 0;
      const probe: ProbeAdapter = {
        name: 'fixture',
        async probe(target) {
          active++;
          peak = Math.max(peak, active);
          await new Promise(resolve => setTimeout(resolve, 1));
          active--;
          completed++;
          return alive(target, { exitFamily: 'ipv4' });
        },
      };
      const checkProxy = new CheckProxy(probe);
      if (kind === 'pool') {
        const app = createHttpApp({version:'test', checkTarget:new CheckTarget({checkProxy,
          resolver:new ResolveTarget({query:async () => ({ok:true, values:[]})})})});
        await new ApiClient({fetchImpl:async (url, init) => app.request(String(url), init)})
          .checkBatch(addresses.join('\n'), undefined, undefined, concurrency);
      } else if (kind === 'domain') {
        await new CheckTarget({ ...(concurrency === undefined ? {} : { concurrency }), checkProxy,
          resolver: new ResolveTarget({ query: async (_name, type) => ({ ok: true, values: type === 'A' ? addresses : [] }) }),
        }).execute('edge.example.com');
      } else {
        const target = normalizeManagedTarget({ domain: 'edge.example.com', mode: 'A', minActive: 0 });
        if (!target) throw new Error('invalid fixture target');
        const dns = { listAddressRecords: async () => addresses.map((content, index) => ({
          id: String(index), type: 'A', name: target.domain, content,
        })) } as unknown as DnsRepository;
        await new MaintainManagedTarget({ ...(concurrency === undefined ? {} : { concurrency }), probe, dns,
          pools: { load: async () => '', save: async () => { throw new Error('unexpected pool write'); },
            addToTrash: async () => { throw new Error('unexpected trash write'); } },
        }).execute({ target, zone: { zoneId: 'fixture-zone', apiToken: 'fixture-token' }, poolKey: 'ip_pool_default' });
      }
      expect(peak).toBe(expectedPeak);
      expect(completed).toBe(addresses.length);
    },
  );
});
