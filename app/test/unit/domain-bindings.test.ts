import { describe, expect, it, vi } from 'vitest';
import { KvDomainBindingRepository } from '../../src/adapters/storage/kv-domain-binding-repository';
import { DomainBindings, DomainBindingsInputError } from '../../src/application/domain-bindings';
import { DEFAULT_POOL_KEY, DOMAIN_POOL_MAPPING_KEY, DOMAIN_POOL_ORDER_KEY } from '../../src/contracts/pool';
import type { ManagedTarget } from '../../src/domain/managed-target';
import type {
  MaintenanceSource,
  MaintenanceSourceData,
  MaintenanceTargetConfig,
} from '../../src/ports/maintenance-source';

function target(domain: string, mode: ManagedTarget['mode'] = 'A'): ManagedTarget {
  return { mode, domain, port: mode === 'TXT' ? null : 443, minActive: 1, exitFilter: 'any', countries: [], asns: [] };
}

function source(data: Partial<MaintenanceSourceData> = {}): MaintenanceSource {
  const targets: MaintenanceTargetConfig[] = [
    { target: target('a.example.com'), zoneIndex: null, enabled: true },
    { target: target('b.example.com'), zoneIndex: null, enabled: true },
  ];
  return { load: async () => ({ zones: [], targets, poolMapping: {}, poolNames: {}, ...data }) };
}

/** 只记录读写的内存仓库，用来断言“写回内容”而不是 KV 细节。 */
function repository(initial: Readonly<Record<string, string>> = {}, initialOrder: readonly string[] = []) {
  let stored: Record<string, string> = { ...initial };
  let order: readonly string[] = [...initialOrder];
  return {
    get stored(): Readonly<Record<string, string>> {
      return stored;
    },
    get order(): readonly string[] {
      return order;
    },
    read: async () => ({ ...stored }),
    write: async (mapping: Readonly<Record<string, string>>) => {
      stored = { ...mapping };
    },
    readOrder: async () => [...order],
    writeOrder: async (next: readonly string[]) => {
      order = [...next];
    },
  };
}

describe('DomainBindings', () => {
  it('lists every target with its resolved pool and display name', async () => {
    const bindings = new DomainBindings(
      source({
        poolMapping: { 'a.example.com|A': 'ip_pool_002', 'b.example.com': 'ip_pool_003' },
        poolNames: { ip_pool_002: '香港池' },
      }),
      repository(),
    );

    await expect(bindings.list()).resolves.toEqual({
      items: [
        {
          key: 'a.example.com|A',
          domain: 'a.example.com',
          mode: 'A',
          poolKey: 'ip_pool_002',
          poolName: '香港池',
          enabled: true,
        },
        {
          key: 'b.example.com|A',
          domain: 'b.example.com',
          mode: 'A',
          poolKey: 'ip_pool_003',
          poolName: '池 003',
          enabled: true,
        },
      ],
    });
  });

  it('falls back to the default pool when the binding is unknown or invalid', async () => {
    const bindings = new DomainBindings(
      source({ poolMapping: { 'a.example.com|A': 'ip_pool_trash', 'b.example.com|A': 'not-a-pool' } }),
      repository(),
    );

    const { items } = await bindings.list();
    expect(items.map((item) => item.poolKey)).toEqual([DEFAULT_POOL_KEY, DEFAULT_POOL_KEY]);
  });

  it('saves whitelisted bindings and never drops unrelated keys', async () => {
    const repo = repository({ 'reserved.example.net|A': 'ip_pool_003', 'a.example.com|A': DEFAULT_POOL_KEY });
    const bindings = new DomainBindings(source(), repo);

    await bindings.save({
      'a.example.com|A': 'ip_pool_002',
      'missing.example.com|A': 'ip_pool_004',
    });

    expect(repo.stored).toEqual({
      'reserved.example.net|A': 'ip_pool_003',
      'a.example.com|A': 'ip_pool_002',
    });
  });

  it('rejects an invalid pool key for a managed target without writing', async () => {
    const repo = repository({ 'reserved.example.net|A': 'ip_pool_003' });
    const bindings = new DomainBindings(source(), repo);

    await expect(bindings.save({ 'a.example.com|A': 'not-a-pool' })).rejects.toThrow('IP 池 key 无效');
    expect(repo.stored).toEqual({ 'reserved.example.net|A': 'ip_pool_003' });
  });

  it('rejects payloads that are not plain objects', async () => {
    const bindings = new DomainBindings(source(), repository());

    await expect(bindings.save(null)).rejects.toBeInstanceOf(DomainBindingsInputError);
    await expect(bindings.save([])).rejects.toBeInstanceOf(DomainBindingsInputError);
    await expect(bindings.save('a.example.com|A')).rejects.toBeInstanceOf(DomainBindingsInputError);
  });
});

  it('applies the saved display order and appends targets that are not listed', async () => {
    const bindings = new DomainBindings(source(), repository({}, ['b.example.com|A']));

    const { items } = await bindings.list();
    expect(items.map((item) => item.key)).toEqual(['b.example.com|A', 'a.example.com|A']);
  });

  it('saves the whole display order only when it matches the current targets', async () => {
    const repo = repository();
    const bindings = new DomainBindings(source(), repo);

    await bindings.saveOrder(['b.example.com|A', 'a.example.com|A']);
    expect(repo.order).toEqual(['b.example.com|A', 'a.example.com|A']);

    await expect(bindings.saveOrder(['b.example.com|A'])).rejects.toThrow('管理域名列表已变化');
    await expect(bindings.saveOrder(['a.example.com|A', 'a.example.com|A'])).rejects.toThrow('管理域名列表已变化');
    await expect(bindings.saveOrder('a.example.com|A')).rejects.toThrow('排序数据格式无效');
    expect(repo.order).toEqual(['b.example.com|A', 'a.example.com|A']);
  });

  it('reads legacy bindings: KV keeps the key lowercase, target domain may arrive uppercase', async () => {
    const targets: MaintenanceTargetConfig[] = [
      { target: target('A.Example.COM.'), zoneIndex: null, enabled: true },
      { target: target('b.example.com'), zoneIndex: null, enabled: true },
    ];
    const bindings = new DomainBindings(
      source({ targets, poolMapping: { 'a.example.com|A': 'ip_pool_003', 'b.example.com': 'ip_pool_004' } }),
      repository(),
    );

    const { items } = await bindings.list();
    expect(items.map((item) => item.key)).toEqual(['a.example.com|A', 'b.example.com|A']);
    expect(items.map((item) => item.poolKey)).toEqual(['ip_pool_003', 'ip_pool_004']);
  });
describe('KvDomainBindingRepository', () => {
  it('drops empty keys and non-whitelist pool keys before writing KV', async () => {
    const put = vi.fn(async () => undefined);
    const kv = { get: vi.fn(async () => null), put } as unknown as KVNamespace;

    await new KvDomainBindingRepository(kv).write({
      ' a.example.com|A ': ' ip_pool_002 ',
      'b.example.com|A': 'ip_pool_trash',
      '': DEFAULT_POOL_KEY,
    });

    expect(put).toHaveBeenCalledWith(
      DOMAIN_POOL_MAPPING_KEY,
      JSON.stringify({ 'a.example.com|A': 'ip_pool_002' }),
    );
  });

  it('normalizes and de-duplicates the display order before writing KV', async () => {
    const put = vi.fn(async () => undefined);
    const kv = { get: vi.fn(async () => null), put } as unknown as KVNamespace;

    await new KvDomainBindingRepository(kv).writeOrder(['B.Example.com|a', 'b.example.com|A', '']);

    expect(put).toHaveBeenCalledWith(DOMAIN_POOL_ORDER_KEY, JSON.stringify(['b.example.com|A']));
  });

  it('drops non-string and duplicate entries when reading the display order', async () => {
    const get = vi.fn(async () => ['b.example.com|A', 42, null, 'B.example.com|a']);
    const repo = new KvDomainBindingRepository({ get, put: vi.fn() } as unknown as KVNamespace);

    await expect(repo.readOrder()).resolves.toEqual(['b.example.com|A']);
  });

  it('treats non-array order data as empty without throwing', async () => {
    const get = vi.fn(async () => 'not-an-array');
    const repo = new KvDomainBindingRepository({ get, put: vi.fn() } as unknown as KVNamespace);

    await expect(repo.readOrder()).resolves.toEqual([]);
  });
});