import { describe, expect, it, vi } from 'vitest';
import { KvPoolCatalog } from '../../src/adapters/storage/kv-pool-catalog';
import {
  DEFAULT_POOL_KEY,
  DOMAIN_POOL_MAPPING_KEY,
  POOL_NAMES_KEY,
  POOL_ORDER_KEY,
  TRASH_POOL_KEY,
} from '../../src/contracts/pool';

function createKv(initial: Readonly<Record<string, string>> = {}) {
  const values = new Map(Object.entries(initial));
  const kv = {
    get: vi.fn(async (key: string, options?: { type?: string }) => {
      const raw = values.get(key) ?? null;
      if (raw === null) return null;
      return options?.type === 'json' ? JSON.parse(raw) : raw;
    }),
    put: vi.fn(async (key: string, value: string) => {
      values.set(key, value);
    }),
    delete: vi.fn(async (key: string) => {
      values.delete(key);
    }),
    list: vi.fn(async () => ({
      keys: [...values.keys()].map((name) => ({ name })),
      list_complete: true,
      cacheStatus: null,
    })),
  } as unknown as KVNamespace;
  return { kv, values };
}

describe('KvPoolCatalog', () => {
  it('lists pools with display names, entry counts and fixed ordering', async () => {
    const { kv } = createKv({
      ip_pool_default: '203.0.113.10:443\n203.0.113.11:443 # note\n# comment only',
      ip_pool_001: '203.0.113.20:443',
      [TRASH_POOL_KEY]: '198.51.100.1:443 # dead',
      [POOL_NAMES_KEY]: JSON.stringify({ ip_pool_001: '香港池' }),
      [POOL_ORDER_KEY]: JSON.stringify(['ip_pool_001', DEFAULT_POOL_KEY]),
    });

    await expect(new KvPoolCatalog(kv).list()).resolves.toEqual([
      { key: DEFAULT_POOL_KEY, name: '默认池', count: 2 },
      { key: 'ip_pool_001', name: '香港池', count: 1 },
      { key: TRASH_POOL_KEY, name: '垃圾桶', count: 1 },
    ]);
  });

  it('always exposes virtual default and trash pools', async () => {
    const { kv } = createKv({ [POOL_NAMES_KEY]: JSON.stringify({ [DEFAULT_POOL_KEY]: '默认池' }) });

    await expect(new KvPoolCatalog(kv).list()).resolves.toEqual([
      { key: DEFAULT_POOL_KEY, name: '默认池', count: 0 },
      { key: TRASH_POOL_KEY, name: '垃圾桶', count: 0 },
    ]);
  });

  it('reads and writes pool text', async () => {
    const { kv, values } = createKv();
    const catalog = new KvPoolCatalog(kv);

    await expect(catalog.read('ip_pool_001')).resolves.toBe('');
    await catalog.write('ip_pool_001', '203.0.113.30:443');
    expect(values.get('ip_pool_001')).toBe('203.0.113.30:443');
    await expect(catalog.exists('ip_pool_001')).resolves.toBe(true);
  });

  it('creates numbered pools and persists custom names and order', async () => {
    const { kv, values } = createKv({ [POOL_ORDER_KEY]: JSON.stringify([DEFAULT_POOL_KEY, TRASH_POOL_KEY]) });
    const catalog = new KvPoolCatalog(kv);

    await expect(catalog.create('香港池')).resolves.toEqual({ key: 'ip_pool_001', name: '香港池', count: 0 });
    expect(values.get('ip_pool_001')).toBe('');
    await expect(catalog.list()).resolves.toContainEqual({ key: 'ip_pool_001', name: '香港池', count: 0 });
    expect(JSON.parse(values.get(POOL_ORDER_KEY) ?? '[]')).toEqual([DEFAULT_POOL_KEY, 'ip_pool_001', TRASH_POOL_KEY]);

    await catalog.rename('ip_pool_001', '池 001');
    expect(JSON.parse(values.get(POOL_NAMES_KEY) ?? '{}')).toEqual({});
  });

  it('deletes pool metadata, order and resets domain mappings', async () => {
    const { kv, values } = createKv({
      ip_pool_001: '203.0.113.30:443',
      [POOL_NAMES_KEY]: JSON.stringify({ ip_pool_001: '香港池' }),
      [POOL_ORDER_KEY]: JSON.stringify([DEFAULT_POOL_KEY, 'ip_pool_001', TRASH_POOL_KEY]),
      [DOMAIN_POOL_MAPPING_KEY]: JSON.stringify({ 'a.example.com': 'ip_pool_001', 'b.example.com': 'ip_pool_002' }),
    });

    await new KvPoolCatalog(kv).remove('ip_pool_001');

    expect(values.has('ip_pool_001')).toBe(false);
    expect(JSON.parse(values.get(POOL_NAMES_KEY) ?? '{}')).toEqual({});
    expect(JSON.parse(values.get(POOL_ORDER_KEY) ?? '[]')).toEqual([DEFAULT_POOL_KEY, TRASH_POOL_KEY]);
    expect(JSON.parse(values.get(DOMAIN_POOL_MAPPING_KEY) ?? '{}')).toEqual({
      'a.example.com': DEFAULT_POOL_KEY,
      'b.example.com': 'ip_pool_002',
    });
  });

  it('normalizes saved order with default first and trash last', async () => {
    const { kv, values } = createKv({ ip_pool_001: '', ip_pool_002: '' });

    await new KvPoolCatalog(kv).saveOrder(['ip_pool_002', TRASH_POOL_KEY, 'ip_pool_001', DEFAULT_POOL_KEY]);

    expect(JSON.parse(values.get(POOL_ORDER_KEY) ?? '[]')).toEqual([
      DEFAULT_POOL_KEY,
      'ip_pool_002',
      'ip_pool_001',
      TRASH_POOL_KEY,
    ]);
  });
});

