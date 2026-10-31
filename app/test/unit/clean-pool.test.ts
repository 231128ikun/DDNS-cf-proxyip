import { describe, expect, it, vi } from 'vitest';

import { CheckPoolText } from '../../src/application/check-pool';
import { CheckProxy } from '../../src/application/check-proxy';
import { CleanPool } from '../../src/application/clean-pool';
import { PoolInputError, PoolService } from '../../src/application/pool-service';
import { DEFAULT_POOL_KEY, TRASH_POOL_KEY } from '../../src/contracts/pool';
import { alive, dead, unknown, type ProbeResult } from '../../src/domain/probe-result';
import type { ProxyTarget } from '../../src/domain/proxy-target';
import type { PoolRepository, TrashCandidate } from '../../src/ports/pool-repository';
import type { ProbeAdapter } from '../../src/ports/probe';
import { MemoryPoolCatalog } from '../helpers/memory-pool-catalog';

/** 按地址前缀给出确定结论：`dead.` 判失效，`flaky.` 模拟探针异常，其余可用。 */
class AddressingProbeAdapter implements ProbeAdapter {
  readonly name = 'addressing';

  async probe(target: ProxyTarget): Promise<ProbeResult> {
    const authority = target.authority ?? '';
    if (authority.startsWith('flaky.')) return unknown(target, 'TIMEOUT', 'timeout');
    if (authority.startsWith('dead.')) return dead(target, { code: 'connect-refused' });
    return alive(target, { endpoint: 'fake', exitIp: '198.51.100.8', exitFamily: 'ipv4' });
  }
}

class RecordingTrashRepository implements PoolRepository {
  readonly batches: (readonly TrashCandidate[])[] = [];

  async load(): Promise<string> {
    return '';
  }

  async save(): Promise<void> {}

  async addToTrash(entries: readonly TrashCandidate[]): Promise<void> {
    this.batches.push([...entries]);
  }
}

function createCleaner(catalog: MemoryPoolCatalog) {
  const trash = new RecordingTrashRepository();
  const adapter = new AddressingProbeAdapter();
  const cleanPool = new CleanPool({
    pools: new PoolService(catalog),
    catalog,
    trash,
    checkPool: new CheckPoolText(new CheckProxy(adapter), 4),
  });
  return { cleanPool, trash, adapter };
}

const poolOf = (...addresses: readonly string[]): string => addresses.join('\n');

describe('一键洗库', () => {
  it('存在未确认项时不写回也不入桶', async () => {
    const catalog = new MemoryPoolCatalog({
      [DEFAULT_POOL_KEY]: poolOf('alive.example:443', 'dead.example:443', 'flaky.example:443'),
    });
    const { cleanPool, trash } = createCleaner(catalog);

    const report = await cleanPool.execute(DEFAULT_POOL_KEY);

    expect(report).toMatchObject({ ok: true, checked: 3, skipped: true, unknown: 1, kept: 0, trashed: 0 });
    expect(catalog.data.get(DEFAULT_POOL_KEY)).toContain('dead.example:443');
    expect(trash.batches).toEqual([]);
  });

  it('失效项进垃圾桶，有效项写回原池', async () => {
    const catalog = new MemoryPoolCatalog({
      [DEFAULT_POOL_KEY]: poolOf('alive.example:443', 'dead.example:443'),
    });
    const { cleanPool, trash } = createCleaner(catalog);

    const report = await cleanPool.execute(DEFAULT_POOL_KEY);

    expect(report).toMatchObject({ ok: true, checked: 2, kept: 1, trashed: 1, unknown: 0, skipped: false });
    const saved = catalog.data.get(DEFAULT_POOL_KEY) ?? '';
    expect(saved).toContain('alive.example:443');
    expect(saved).not.toContain('dead.example:443');

    const candidates = trash.batches.flat();
    expect(candidates).toHaveLength(1);
    expect(candidates[0]?.entryLine).toContain('dead.example:443');
    expect(candidates[0]?.reason).toBe('洗库失效');
    expect(candidates[0]?.poolKey).toBe(DEFAULT_POOL_KEY);
  });

  it('空池直接报错，不触发检测', async () => {
    const { cleanPool } = createCleaner(new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: '' }));
    await expect(cleanPool.execute(DEFAULT_POOL_KEY)).rejects.toThrow('池为空');
  });

  it('洗垃圾桶只做恢复，不把失效项再写回桶里', async () => {
    const catalog = new MemoryPoolCatalog({
      [TRASH_POOL_KEY]: 'alive.example:443,null,null,v4 # 维护失效 2026-01-01 来自 ip_pool_001',
      ip_pool_001: '',
    });
    const { cleanPool, trash } = createCleaner(catalog);

    const report = await cleanPool.execute(TRASH_POOL_KEY);

    expect(report).toMatchObject({ ok: true, kept: 1, trashed: 0, skipped: false });
    expect(catalog.data.get('ip_pool_001')).toContain('alive.example:443');
    expect(trash.batches).toEqual([]);
  });
});

describe('一键洗库完整性边界', () => {
  const entries = Array.from({ length: 200 }, (_, index) => `node-${index}.example:443,AS64500,JP,v4 # 用户备注${index}`);

  it.each([DEFAULT_POOL_KEY, TRASH_POOL_KEY])('201 个有效地址拒绝洗库且不修改 %s 或垃圾桶', async (poolKey) => {
    const content = [...entries, 'extra.example:443 # 不得丢失'].join('\n');
    const catalog = new MemoryPoolCatalog({ [poolKey]: content, ip_pool_001: 'existing.example:443 # 原池' });
    const snapshot = new Map(catalog.data);
    const { cleanPool, trash, adapter } = createCleaner(catalog);
    const write = vi.spyOn(catalog, 'write');
    const probe = vi.spyOn(adapter, 'probe');

    await expect(cleanPool.execute(poolKey)).rejects.toThrow(PoolInputError);
    expect(probe).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
    expect(catalog.data).toEqual(snapshot);
    expect(trash.batches).toEqual([]);
  });

  it('200 个有效地址正常洗库并保留全部元数据和备注', async () => {
    const catalog = new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: entries.join('\n') });
    const { cleanPool, trash } = createCleaner(catalog);
    expect(await cleanPool.execute(DEFAULT_POOL_KEY)).toMatchObject({ checked: 200, kept: 200, skipped: false });
    expect(catalog.data.get(DEFAULT_POOL_KEY)).toBe(entries.join('\n'));
    expect(trash.batches).toEqual([]);
  });

  it('规范化重复地址不造成超限', async () => {
    const catalog = new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: [...entries, 'NODE-0.EXAMPLE', 'node-199.example:443'].join('\n') });
    const { cleanPool } = createCleaner(catalog);
    expect(await cleanPool.execute(DEFAULT_POOL_KEY)).toMatchObject({ checked: 200, kept: 200, skipped: false });
  });

  it('第 200 个有效地址后的无效项阻止整池写回', async () => {
    const content = [...entries, '203.0.113.999:443'].join('\n');
    const catalog = new MemoryPoolCatalog({ [DEFAULT_POOL_KEY]: content });
    const { cleanPool, trash } = createCleaner(catalog);
    const write = vi.spyOn(catalog, 'write');
    expect(await cleanPool.execute(DEFAULT_POOL_KEY)).toMatchObject({ checked: 200, unknown: 1, skipped: true });
    expect(write).not.toHaveBeenCalled();
    expect(catalog.data.get(DEFAULT_POOL_KEY)).toBe(content);
    expect(trash.batches).toEqual([]);
  });
});
