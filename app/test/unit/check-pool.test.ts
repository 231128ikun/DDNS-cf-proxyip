import { describe, expect, it, vi } from 'vitest';
import { CheckPoolText } from '../../src/application/check-pool';
import { CheckProxy } from '../../src/application/check-proxy';
import { PoolInputError } from '../../src/application/pool-service';
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
  const addresses = Array.from({ length: 200 }, (_, index) => `node-${index}.example:443`);
  const probe = () => vi.fn(async (target: Parameters<ProbeAdapter['probe']>[0]) => alive(target, { exitFamily: 'ipv4' }));

  it('rejects the 201st distinct valid target before starting any probe', async () => {
    const run = probe();
    const checker = new CheckPoolText(new CheckProxy({ name: 'fake', probe: run }));
    await expect(checker.execute([...addresses, 'extra.example:443'].join('\n'))).rejects.toThrow(PoolInputError);
    expect(run).not.toHaveBeenCalled();
  });

  it('accepts 200 targets without inflating default-port/case duplicates', async () => {
    const run = probe();
    const checker = new CheckPoolText(new CheckProxy({ name: 'fake', probe: run }));
    const report = await checker.execute([...addresses, 'NODE-0.EXAMPLE', 'node-199.example:443'].join('\n'));
    expect(report).toMatchObject({ total: 200, alive: 200, invalid: [] });
    expect(run).toHaveBeenCalledTimes(200);
  });

  it('reports an invalid target after the 200th valid entry', async () => {
    const checker = new CheckPoolText(new CheckProxy({ name: 'fake', probe: probe() }));
    const report = await checker.execute([...addresses, '203.0.113.999:443'].join('\n'));
    expect(report.total).toBe(200);
    expect(report.invalid).toEqual(['203.0.113.999:443']);
  });
});
