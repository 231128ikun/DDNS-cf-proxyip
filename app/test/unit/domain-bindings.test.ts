import { describe, expect, it, vi } from 'vitest';
import { KvDomainBindingRepository } from '../../src/adapters/storage/kv-domain-binding-repository';
import { DomainBindings, DomainBindingsInputError } from '../../src/application/domain-bindings';
import { DEFAULT_POOL_KEY, DOMAIN_POOL_MAPPING_KEY } from '../../src/contracts/pool';
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
function repository(initial: Readonly<Record<string, string>> = {}) {
  let stored: Record<string, string> = { ...initial };
  return {
    get stored(): Readonly<Record<string, string>> {
      return stored;
    },
    read: async () => ({ ...stored }),
    write: async (mapping: Readonly<Record<string, string>>) => {
      stored = { ...mapping };
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
});