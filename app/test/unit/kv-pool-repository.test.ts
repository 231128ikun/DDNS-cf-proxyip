import { describe, expect, it, vi } from 'vitest';
import { KvPoolRepository } from '../../src/adapters/storage/kv-pool-repository';
import { TRASH_POOL_KEY } from '../../src/contracts/pool';

function createKv(initial: Readonly<Record<string, string>> = {}): {
  kv: KVNamespace;
  values: Map<string, string>;
  put: ReturnType<typeof vi.fn>;
} {
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

describe('KvPoolRepository', () => {
  it('loads a missing pool as an empty string and saves content', async () => {
    const { kv, values } = createKv();
    const repository = new KvPoolRepository(kv);

    await expect(repository.load('ip_pool_custom')).resolves.toBe('');
    await repository.save('ip_pool_custom', '203.0.113.10:443');

    expect(values.get('ip_pool_custom')).toBe('203.0.113.10:443');
  });

  it('deduplicates trash entries while preserving known pool metadata', async () => {
    const existing = '198.51.100.1:443,AS64500,JP,v4 # old';
    const { kv, values } = createKv({ [TRASH_POOL_KEY]: existing });
    const repository = new KvPoolRepository(kv, {
      now: () => new Date('2026-09-24T00:00:00.000Z'),
    });

    await repository.addToTrash([
      { entryLine: '198.51.100.1:443 # duplicate', reason: '重复', poolKey: 'ip_pool_default' },
      { entryLine: '203.0.113.10:8443,AS64501,SG,v4 # edge', reason: '维护失效', poolKey: 'ip_pool_custom' },
    ]);

    const lines = values.get(TRASH_POOL_KEY)?.split('\n') ?? [];
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe(existing);
    expect(lines[1]).toContain('203.0.113.10:8443,AS64501,SG,v4 # 维护失效');
    expect(lines[1]).toContain('来自 ip_pool_custom');
  });

  it('keeps only the newest entries when maxTrashSize is exceeded', async () => {
    const { kv, values } = createKv({
      [TRASH_POOL_KEY]: '198.51.100.1:443 # one\n198.51.100.2:443 # two',
    });
    const repository = new KvPoolRepository(kv, { maxTrashSize: 2 });

    await repository.addToTrash([{ entryLine: '203.0.113.10:443', reason: 'dead' }]);

    const lines = values.get(TRASH_POOL_KEY)?.split('\n') ?? [];
    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain('198.51.100.2:443');
    expect(lines[1]).toContain('203.0.113.10:443');
  });

  it('does not write when the trash batch is empty', async () => {
    const { kv, put } = createKv();
    const repository = new KvPoolRepository(kv);

    await repository.addToTrash([]);

    expect(put).not.toHaveBeenCalled();
  });
});
