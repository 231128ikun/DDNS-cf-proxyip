import { describe, expect, it, vi } from 'vitest';
import { CONFIG_KEY, KvConfigRepository } from '../../src/adapters/storage/kv-config-repository';
import { KvMaintenanceSource } from '../../src/adapters/storage/kv-maintenance-source';
import { loadEnvConfig } from '../../src/config/runtime';
import { createDefaultConfig, parseAppConfig } from '../../src/contracts/config';
import { DOMAIN_POOL_MAPPING_KEY, POOL_NAMES_KEY } from '../../src/contracts/pool';

function createKv(values: Readonly<Record<string, string>> = {}) {
  return { get: vi.fn(async (key: string, options?: { type: 'text' | 'json' }) => {
    const raw = values[key] ?? null;
    return raw !== null && options?.type === 'json' ? JSON.parse(raw) : raw;
  }) };
}

describe('maintenance configuration snapshot', () => {
  it('uses the same normalized default minimum as the panel for an old KV record', async () => {
    const kv = createKv({ [CONFIG_KEY]: JSON.stringify({
      settings: { DEFAULT_MIN_ACTIVE: 5 },
      targets: [{ domain: 'proxy.example.com', mode: 'A' }],
    }) });
    const loaded = await new KvConfigRepository(kv as unknown as KVNamespace).load(loadEnvConfig({}));
    expect(loaded.status).toBe('loaded');
    if (loaded.status !== 'loaded') throw new Error('configuration failed to load');
    const data = await new KvMaintenanceSource(kv as unknown as KVNamespace, loaded.config).load();
    expect(loaded.config.targets[0]?.minActive).toBe(5);
    expect(data.targets[0]?.target.minActive).toBe(loaded.config.targets[0]?.minActive);
    expect(kv.get.mock.calls.filter(([key]) => key === CONFIG_KEY)).toHaveLength(1);
  });

  it('preserves normalized A and TXT targets, zone indexes and exit constraints', async () => {
    const parsed = parseAppConfig({
      zones: [{ baseDomain: 'example.com', zoneId: 'zone-test', apiKey: 'token-test' }],
      targets: [
        { domain: 'a.example.com', mode: 'A', port: 8443, minActive: 3, zoneIndex: 0, exitFilter: 'ipv4_only', country: 'jp', asn: 'AS64500' },
        { domain: 'txt.example.com', mode: 'TXT', port: 'any', minActive: 2, enabled: false },
      ],
    });
    if (!parsed.ok) throw new Error(parsed.message);
    const data = await new KvMaintenanceSource(createKv() as unknown as KVNamespace, parsed.value).load();
    expect(data.zones).toEqual([{ zoneId: 'zone-test', apiToken: 'token-test' }]);
    expect(data.targets).toMatchObject([
      { target: { domain: 'a.example.com', mode: 'A', port: 8443, minActive: 3, exitFilter: 'v4', countries: ['JP'], asns: ['64500'] }, zoneIndex: 0, enabled: true },
      { target: { domain: 'txt.example.com', mode: 'TXT', port: null, minActive: 2 }, zoneIndex: null, enabled: false },
    ]);
  });

  it('reads only pool binding metadata and never reparses a different app_config', async () => {
    const kv = createKv({
      [CONFIG_KEY]: '{invalid configuration',
      [DOMAIN_POOL_MAPPING_KEY]: JSON.stringify({ 'proxy.example.com|A': 'ip_pool_001' }),
      [POOL_NAMES_KEY]: JSON.stringify({ ip_pool_001: 'Test pool' }),
    });
    const data = await new KvMaintenanceSource(kv as unknown as KVNamespace, createDefaultConfig()).load();
    expect(data).toEqual({ zones: [], targets: [], poolMapping: { 'proxy.example.com|A': 'ip_pool_001' }, poolNames: { ip_pool_001: 'Test pool' } });
    expect(kv.get.mock.calls.map(([key]) => key).sort()).toEqual([DOMAIN_POOL_MAPPING_KEY, POOL_NAMES_KEY].sort());
  });
});
