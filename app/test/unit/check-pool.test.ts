import { describe, expect, it, vi } from 'vitest';
import { CheckPoolText } from '../../src/application/check-pool';
import { CheckProxy } from '../../src/application/check-proxy';
import { alive } from '../../src/domain/probe-result';
import type { ProbeAdapter } from '../../src/ports/probe';

describe('CheckPoolText progress', () => {
  it('reports each completed target as it finishes', async () => {
    const adapter: ProbeAdapter = {
      name: 'fake',
      async probe(target) {
        return alive(target, { exitFamily: 'ipv4' });
      },
    };
    const events: Array<{ address: string; completed: number; total: number }> = [];
    const checkPool = new CheckPoolText(new CheckProxy(adapter), 1);

    const report = await checkPool.execute(
      '203.0.113.10\n203.0.113.11:443',
      {},
      ({ item, completed, total }) => events.push({ address: item.address, completed, total }),
    );

    expect(events).toEqual([
      { address: '203.0.113.10:443', completed: 1, total: 2 },
      { address: '203.0.113.11:443', completed: 2, total: 2 },
    ]);
    expect(report.total).toBe(2);
  });
});

describe('CheckPoolText complete-input validation', () => {
  const addresses = Array.from({ length: 1205 }, (_, index) => `node-${index}.example:443`);
  const probe = () => vi.fn(async (target: Parameters<ProbeAdapter['probe']>[0]) => alive(target, { exitFamily: 'ipv4' }));

  it('checks all distinct targets without a fixed quantity cap and respects concurrency', async () => {
    let active = 0, peak = 0;
    const run = probe();
    const checker = new CheckPoolText(new CheckProxy({ name: 'fake', probe: async target => {
      peak = Math.max(peak, ++active); await Promise.resolve(); const result = await run(target); active--; return result;
    } }), 4);
    expect(await checker.execute(addresses.join('\n'))).toMatchObject({ total: 1205, alive: 1205 });
    expect(run).toHaveBeenCalledTimes(1205); expect(peak).toBeLessThanOrEqual(4);
  });

  it('deduplicates default-port/case variants in a large pool', async () => {
    const run = probe();
    const checker = new CheckPoolText(new CheckProxy({ name: 'fake', probe: run }));
    const report = await checker.execute([...addresses, 'NODE-0.EXAMPLE', 'node-199.example:443'].join('\n'));
    expect(report).toMatchObject({ total: 1205, alive: 1205, invalid: [] });
    expect(run).toHaveBeenCalledTimes(1205);
  });

  it('reports invalid input after all valid entries without truncation', async () => {
    const checker = new CheckPoolText(new CheckProxy({ name: 'fake', probe: probe() }));
    const report = await checker.execute([...addresses, '203.0.113.999:443'].join('\n'));
    expect(report.total).toBe(1205);
    expect(report.invalid).toEqual(['203.0.113.999:443']);
  });
});

it('checks a duplicate address once while retaining complementary metadata from every source row', async () => {
  const probe = vi.fn(async target => alive(target, { exitFamily: 'unknown' }));
  const report = await new CheckPoolText(new CheckProxy({ name: 'fixture', probe })).execute(
    '203.0.113.10:443,null,JP,v4 # old\n203.0.113.10:443,AS64500,null,null # new',
  );
  expect(probe).toHaveBeenCalledTimes(1);
  expect(report.items[0]!.entry).toMatchObject({ asn: 'AS64500', country: 'JP', stack: 'v4', comment: '# new' });
});
