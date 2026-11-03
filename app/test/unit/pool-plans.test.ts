import { describe, expect, it, vi } from 'vitest';
import { readPoolSnapshot } from '../../src/domain/pool-snapshot';
import { planPoolSave, planPoolRestore, planPoolCleaning } from '../../src/domain/pool-mutation';
import { planTrashAppend, sourcePoolFromTrash } from '../../src/domain/trash';
import { executePoolWrites, PoolWriteError } from '../../src/application/pool-write';
import { DEFAULT_POOL_KEY, TRASH_POOL_KEY } from '../../src/contracts/pool';
import { alive, dead, unknown } from '../../src/domain/probe-result';
import { parseProxyTarget } from '../../src/domain/proxy-target';

const address = '203.0.113.10:443';
const target = parseProxyTarget(address)!;

describe('pure pool mutation plans', () => {
  it('plans append, replace and remove without mutating the source snapshot', () => {
    const before = readPoolSnapshot(`${address},AS64500,JP,v4 # old`);
    const incoming = readPoolSnapshot(`${address},null,null,null # new\n[2001:db8::10]:8443`);
    const appended = planPoolSave(DEFAULT_POOL_KEY, before, incoming, 'append');
    expect(appended.summary).toEqual({ mode: 'append', count: 2, added: 1, removed: 0, replaced: 0 });
    expect(appended.write.after).toContain(`${address},AS64500,JP,v4 # new`);
    expect(appended.changes.map(item => item.kind)).toEqual(['update', 'add']);
    expect(before.entries.size).toBe(1);
    expect(before.text).toContain('# old');
    expect(planPoolSave(DEFAULT_POOL_KEY, before, incoming, 'replace').summary.replaced).toBe(1);
    expect(planPoolSave(DEFAULT_POOL_KEY, before, incoming, 'remove').summary.removed).toBe(1);
  });

  it('identifies an unchanged canonical save', () => {
    const before = readPoolSnapshot(`${address},AS64500,JP,v4`);
    const plan = planPoolSave(DEFAULT_POOL_KEY, before, before, 'append');
    expect(plan.changed).toBe(false);
    expect(plan.changes).toEqual([]);
  });

  it('plans restore destinations before trash cleanup and reports already-present addresses', () => {
    const trash = readPoolSnapshot(`${address},AS64500,JP,v4 # dead 来自 ip_pool_001`);
    const plan = planPoolRestore(trash, new Map([['ip_pool_001', readPoolSnapshot('')]]), new Map([[address, 'ip_pool_001']]));
    expect(plan.writes.map(write => write.poolKey)).toEqual(['ip_pool_001', TRASH_POOL_KEY]);
    expect(plan.summary).toEqual({ restored: 1, restoredByPool: { ip_pool_001: 1 } });
    expect(plan.writes[0]!.after).toBe(`${address},AS64500,JP,v4`);
    expect(plan.writes[1]!.after).toBe('');
    const repeat = planPoolRestore(trash, new Map([['ip_pool_001', readPoolSnapshot(plan.writes[0]!.after)]]), new Map([[address, 'ip_pool_001']]));
    expect(repeat.summary.restored).toBe(0);
    expect(repeat.writes.map(write => write.poolKey)).toEqual([TRASH_POOL_KEY]);
  });

  it('classifies inspection results without IO and keeps unknown cleaning all-or-nothing', () => {
    const entry = readPoolSnapshot(address).entries.values().next().value!.entry;
    const item = { address, entry, result: dead(target, { code: 'TIMEOUT' }) };
    const report = { total: 1, unknown: 0, invalid: [], items: [item] };
    const plan = planPoolCleaning(DEFAULT_POOL_KEY, report);
    expect(plan.trash).toEqual([{ entryLine: `${address},null,null,null`, reason: '洗库失效', poolKey: DEFAULT_POOL_KEY }]);
    expect(plan.summary).toEqual({ checked: 1, kept: 0, trashed: 1, unknown: 0, skipped: false });
    expect(planPoolCleaning(DEFAULT_POOL_KEY, { ...report, unknown: 1, items: [{ ...item, result: unknown(target, 'HTTP_ERROR', '500') }] }).summary.skipped).toBe(true);
    expect(planPoolCleaning(TRASH_POOL_KEY, { ...report, items: [{ ...item, result: alive(target) }] }).restoreAddresses).toEqual([address]);
  });
});

describe('ordered writes and trash policy', () => {
  it('reports completed writes without pretending a later failure rolled them back', async () => {
    const write = vi.fn(async (key: string) => { if (key === 'ip_pool_002') throw new Error('destination failure'); });
    const plan = ['ip_pool_001', 'ip_pool_002', TRASH_POOL_KEY].map(poolKey => ({ poolKey, before: '', after: address }));
    const failure = await executePoolWrites(plan, write).catch(error => error);
    expect(failure).toBeInstanceOf(PoolWriteError);
    expect(failure).toMatchObject({ failedPoolKey: 'ip_pool_002', completedPoolKeys: ['ip_pool_001'], message: 'destination failure' });
    expect(write.mock.calls.map(call => call[0])).toEqual(['ip_pool_001', 'ip_pool_002']);
  });

  it('uses a pure, deduplicated and capped trash format with the same source marker', () => {
    const candidate = { entryLine: `${address},AS64500,JP,v4 # note`, reason: '洗库失效', poolKey: DEFAULT_POOL_KEY };
    const plan = planTrashAppend('', [candidate, candidate], { timestamp: '2026-11-03 13:00:00', maxSize: 1 });
    expect(plan.content).toBe(`${address},AS64500,JP,v4 # 洗库失效 2026-11-03 13:00:00 来自 ${DEFAULT_POOL_KEY}`);
    expect(sourcePoolFromTrash(plan.content)).toBe(DEFAULT_POOL_KEY);
    expect(sourcePoolFromTrash('example:443 # no source')).toBeNull();
    expect(planTrashAppend(plan.content, [candidate], { timestamp: 'later', maxSize: 1 }).changed).toBe(false);
  });
});
