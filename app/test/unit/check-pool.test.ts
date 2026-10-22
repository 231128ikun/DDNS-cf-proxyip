import { describe, expect, it } from 'vitest';
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
