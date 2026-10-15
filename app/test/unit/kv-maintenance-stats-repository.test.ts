import { describe, expect, it, vi } from 'vitest';

import { KvMaintenanceStatsRepository } from '../../src/adapters/storage/kv-maintenance-stats-repository';
import { POOL_STATS_BASELINE_KEY } from '../../src/contracts/pool';
import type { PoolCatalog } from '../../src/ports/pool-catalog';
import type { PoolSummary } from '../../src/contracts/pool';

function createKv(initial: Readonly<Record<string, string>> = {}) {
  const values = new Map(Object.entries(initial));
  const put = vi.fn(async (key: string, value: string) => {
    values.set(key, value);
  });
  const kv = {
    get: vi.fn(async (key: string) => values.get(key) ?? null),
    put,
  } as unknown as KVNamespace;
  return { kv, values, put };
}

function createCatalog(pools: readonly PoolSummary[] = []): PoolCatalog {
  return {
    list: vi.fn(async () => pools),
    read: vi.fn(async () => ''),
    write: vi.fn(async () => undefined),
    create: vi.fn(async () => pools[0] ?? { key: 'ip_pool_001', name: '池 001', count: 0 }),
    rename: vi.fn(async () => undefined),
    exists: vi.fn(async () => true),
    remove: vi.fn(async () => undefined),
    saveOrder: vi.fn(async () => undefined),
  };
}

describe('KvMaintenanceStatsRepository', () => {
  it('reads current pool summaries and valid baselines', async () => {
    const { kv } = createKv({
      [POOL_STATS_BASELINE_KEY]: JSON.stringify({ ip_pool_default: 2, ip_pool_trash: 1 }),
    });
    const repository = new KvMaintenanceStatsRepository(kv, createCatalog([
      { key: 'ip_pool_default', name: '默认池', count: 2 },
    ]));

    await expect(repository.current()).resolves.toEqual([
      { key: 'ip_pool_default', name: '默认池', count: 2 },
    ]);
    await expect(repository.loadBaseline()).resolves.toEqual({ ip_pool_default: 2, ip_pool_trash: 1 });
  });

  it('treats missing or invalid baselines as absent instead of failing maintenance', async () => {
    const missing = new KvMaintenanceStatsRepository(createKv().kv, createCatalog());
    await expect(missing.loadBaseline()).resolves.toBeNull();

    const invalid = new KvMaintenanceStatsRepository(createKv({
      [POOL_STATS_BASELINE_KEY]: 'not-json',
    }).kv, createCatalog());
    await expect(invalid.loadBaseline()).resolves.toBeNull();
  });

  it('saves the baseline as JSON after a successful notification', async () => {
    const { kv, values, put } = createKv();
    const repository = new KvMaintenanceStatsRepository(kv, createCatalog());

    await repository.saveBaseline({ ip_pool_default: 0, ip_pool_trash: 1 });

    expect(put).toHaveBeenCalledWith(POOL_STATS_BASELINE_KEY, JSON.stringify({ ip_pool_default: 0, ip_pool_trash: 1 }));
    expect(JSON.parse(values.get(POOL_STATS_BASELINE_KEY) ?? '{}')).toEqual({
      ip_pool_default: 0,
      ip_pool_trash: 1,
    });
  });
});