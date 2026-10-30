import { describe, expect, it, vi } from 'vitest';
import { CONFIG_KEY, KvConfigRepository } from '../../src/adapters/storage/kv-config-repository';
import { ConfigService } from '../../src/application/config-service';
import { loadEnvConfig } from '../../src/config/runtime';
import { createDefaultConfig, type AppConfig } from '../../src/contracts/config';

describe('KV configuration storage', () => {
  it('uses environment defaults for runtime fields missing from an old KV record', async () => {
    const store = new Map([[CONFIG_KEY, JSON.stringify({ settings: { CHECK_TIMEOUT: 8_000 } })]]);
    const service = new ConfigService({ repository: new KvConfigRepository(createKv(store)),
      envConfig: loadEnvConfig({ CONCURRENT_CHECKS: '7', DOH_TIMEOUT: '9000' }) });
    await expect(service.resolve()).resolves.toMatchObject({ source: 'kv', config: {
      settings: { CHECK_TIMEOUT: 8_000, CONCURRENT_CHECKS: 7, DOH_TIMEOUT: 9_000 },
    } });
  });

  it('preserves old browser and DNS settings across read/save and takes KV over environment', async () => {
    const store = new Map([[CONFIG_KEY, JSON.stringify({ settings: { CONCURRENT_CHECKS: 7, DOH_TIMEOUT: 9_000 } })]]);
    const repository = new KvConfigRepository(createKv(store));
    const service = new ConfigService({ repository, envConfig: loadEnvConfig({ CONCURRENT_CHECKS: '2', DOH_TIMEOUT: '11000' }) });
    const resolved = await service.resolve();
    expect(resolved).toMatchObject({ source: 'kv', config: { settings: { CONCURRENT_CHECKS: 7, DOH_TIMEOUT: 9_000 } } });
    await service.save(resolved.config);
    expect(JSON.parse(store.get(CONFIG_KEY)!)).toMatchObject({ settings: { CONCURRENT_CHECKS: 7, DOH_TIMEOUT: 9_000 } });
    expect([...store.keys()]).toEqual(['app_config']);
    await expect(repository.load()).resolves.toMatchObject({
      status: 'loaded', config: { settings: { CONCURRENT_CHECKS: 7, DOH_TIMEOUT: 9_000 } },
    });
    store.delete(CONFIG_KEY);
    await expect(service.resolve()).resolves.toMatchObject({
      source: 'env', config: { settings: { CONCURRENT_CHECKS: 2, DOH_TIMEOUT: 11_000 } },
    });
  });

  it('loads the original app_config record directly', async () => {
    const store = new Map<string, string>([
      [CONFIG_KEY, JSON.stringify({
        checkApi: 'https://primary.example/?proxyip=',
        checkApiBackup: '',
        tgToken: 'tg-token',
        tgId: '42',
        projectUrl: 'https://github.com/example/project',
        settings: { CHECK_TIMEOUT: 8_000, CONCURRENT_CHECKS: 5 },
        zones: [{ name: '主域名', baseDomain: 'example.com', zoneId: 'zone-1', apiKey: 'cf-token' }],
        targets: [{
          mode: 'TXT',
          domain: '_proxy.example.com',
          baseDomain: 'example.com',
          prefix: '_proxy',
          zoneIndex: 0,
          port: 'any',
          minActive: 2,
          exitFilter: 'v4',
          country: 'US',
          asn: 'AS64500',
          enabled: true,
        }],
      })],
    ]);

    const result = await new KvConfigRepository(createKv(store)).load();

    expect(result.status).toBe('loaded');
    if (result.status !== 'loaded') return;
    expect(result.source).toBe('kv');
    expect([...store.keys()]).toEqual([CONFIG_KEY]);
    expect(result.config).toMatchObject({
      apiKey: 'cf-token',
      zoneId: 'zone-1',
      checkApi: 'https://primary.example/?proxyip=',
      checkApiBackup: '',
      tgToken: 'tg-token',
      tgId: '42',
      projectUrl: 'https://github.com/example/project',
      settings: { CHECK_TIMEOUT: 8_000, CONCURRENT_CHECKS: 5 },
      zones: [{ name: '主域名', label: '主域名', baseDomain: 'example.com', zoneId: 'zone-1', apiKey: 'cf-token' }],
      targets: [{
        mode: 'TXT',
        domain: '_proxy.example.com',
        country: 'US',
        asn: '64500',
        countries: ['US'],
        asns: ['64500'],
        port: 'any',
      }],
    });
  });

  it('saves only app_config and keeps the original flat shape', async () => {
    const store = new Map<string, string>();
    const kv = createKv(store);
    const repository = new KvConfigRepository(kv);
    const config = validConfig();

    await repository.save(config);

    expect(store.has(CONFIG_KEY)).toBe(true);
    const raw = JSON.parse(store.get(CONFIG_KEY) ?? '{}') as Record<string, unknown>;
    expect(raw).toMatchObject({
      checkApi: 'https://primary.example/?proxyip=',
      settings: { CONCURRENT_CHECKS: 5, CHECK_TIMEOUT: 9_000 },
      zones: [{ name: '主域名', label: '主域名' }],
      targets: [{ mode: 'TXT', port: 'any', country: 'US', asn: '64500' }],
    });
    expect([...store.keys()]).toEqual([CONFIG_KEY]);
    expect(raw).not.toHaveProperty('probe');
    expect(raw).not.toHaveProperty('schemaVersion');

    await expect(repository.load()).resolves.toEqual({ status: 'loaded', source: 'kv', config });
  });

  it('reports invalid JSON without writing anything', async () => {
    const store = new Map<string, string>([[CONFIG_KEY, '{bad json']]);
    const kv = createKv(store);

    await expect(new KvConfigRepository(kv).load()).resolves.toEqual({
      status: 'invalid',
      source: 'kv',
      message: 'KV 内容不是有效 JSON',
    });
    expect(kv.put).not.toHaveBeenCalled();
  });

  it('keeps explicit empty optional endpoints', async () => {
    const store = new Map<string, string>([
      [CONFIG_KEY, JSON.stringify({ checkApi: 'https://primary.example/?proxyip=', checkApiBackup: '' })],
    ]);

    const result = await new KvConfigRepository(createKv(store)).load();

    expect(result).toMatchObject({
      status: 'loaded',
      config: { checkApi: 'https://primary.example/?proxyip=', checkApiBackup: '' },
    });
  });
});

function createKv(store: Map<string, string>): KVNamespace & { readonly put: ReturnType<typeof vi.fn> } {
  return {
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    put: vi.fn(async (key: string, value: string) => {
      store.set(key, value);
    }),
  } as unknown as KVNamespace & { readonly put: ReturnType<typeof vi.fn> };
}

function validConfig(): AppConfig {
  const defaults = createDefaultConfig();
  return {
    ...defaults,
    apiKey: 'cf-token',
    zoneId: 'zone-1',
    zones: [{ name: '主域名', baseDomain: 'example.com', zoneId: 'zone-1', apiKey: 'cf-token', label: '主域名' }],
    targets: [{
      mode: 'TXT',
      domain: '_proxy.example.com',
      baseDomain: 'example.com',
      prefix: '_proxy',
      zoneIndex: 0,
      port: 'any',
      minActive: 3,
      exitFilter: 'any',
      country: 'US',
      asn: '64500',
      countries: ['US'],
      asns: ['64500'],
      enabled: true,
    }],
    checkApi: 'https://primary.example/?proxyip=',
    checkApiBackup: '',
    tgToken: 'tg-token',
    tgId: '42',
    projectUrl: 'https://github.com/example/project',
    settings: { ...defaults.settings, CONCURRENT_CHECKS: 5, CHECK_TIMEOUT: 9_000 },
  };
}
