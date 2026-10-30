import { describe, expect, it } from 'vitest';
import { createProbeAdapterFromConfig, loadEnvConfig } from '../../src/config/runtime';
import { createDefaultConfig, parseRuntimeSettings, toProbeConfig } from '../../src/contracts/config';
import { parseProxyTarget } from '../../src/domain/proxy-target';

const target = parseProxyTarget('203.0.113.10:443');
if (!target) throw new Error('test target is invalid');

describe('runtime configuration', () => {
  it.each([
    [{}, 32, 5_000],
    [{ CONCURRENT_CHECKS: 7, DOH_TIMEOUT: 9_000 }, 7, 9_000],
    [{ CONCURRENT_CHECKS: 0, DOH_TIMEOUT: 10 }, 1, 1_000],
    [{ CONCURRENT_CHECKS: 999, DOH_TIMEOUT: 90_000 }, 128, 30_000],
    [{ CONCURRENT_CHECKS: 'bad', DOH_TIMEOUT: null }, 32, 5_000],
  ])('retains and bounds the original browser and DNS settings: %j', (raw, concurrency, timeout) => {
    expect(parseRuntimeSettings(raw)).toMatchObject({ CONCURRENT_CHECKS: concurrency, DOH_TIMEOUT: timeout });
  });

  it('drops the retired backend setting without changing the shared concurrency', () => {
    const settings = parseRuntimeSettings({ CONCURRENT_CHECKS: 24, BACKEND_CONCURRENT_CHECKS: 1 });
    expect(settings.CONCURRENT_CHECKS).toBe(24);
    expect(settings).not.toHaveProperty('BACKEND_CONCURRENT_CHECKS');
  });

  it('uses environment browser and DNS settings only as configuration fallback', () => {
    const config = loadEnvConfig({ CONCURRENT_CHECKS: '7', DOH_TIMEOUT: '9000' });
    expect(config.settings).toMatchObject({ CONCURRENT_CHECKS: 7, DOH_TIMEOUT: 9_000 });
    expect(loadEnvConfig({ CONCURRENT_CHECKS: '999', DOH_TIMEOUT: '10' }).settings)
      .toMatchObject({ CONCURRENT_CHECKS: 128, DOH_TIMEOUT: 1_000 });
  });

  it('clamps the probe timeout and keeps the configured endpoint template', () => {
    const config = loadEnvConfig({
      CHECK_API: 'https://probe.example/check?proxyip={proxyip}',
      // 显式清空备用接口，才能单独断言主接口模板；未设置时会保留内置备用接口。
      CHECK_API_BACKUP: '',
      CHECK_TIMEOUT: '10',
    });

    expect(config.settings.CHECK_TIMEOUT).toBe(500);
    expect(toProbeConfig(config).endpoints).toEqual([
      { name: 'primary', urlTemplate: 'https://probe.example/check?proxyip={proxyip}' },
    ]);
  });

  it('drops blank endpoint variables instead of keeping an empty endpoint', () => {
    const config = loadEnvConfig({
      CHECK_API: '   ',
      CHECK_API_BACKUP: 'https://backup.example/check?proxyip={proxyip}',
    });

    expect(toProbeConfig(config).endpoints.map((endpoint) => endpoint.name)).toEqual(['backup']);
  });

  it('falls back to the built-in backup endpoint when the variables are undefined', () => {
    const defaults = createDefaultConfig();
    const config = loadEnvConfig({});

    expect(config.checkApi).toBe(defaults.checkApi);
    expect(config.checkApiBackup).toBe(defaults.checkApiBackup);
  });

  it('returns unknown instead of dead when no endpoint is configured', async () => {
    const defaults = createDefaultConfig();
    const adapter = createProbeAdapterFromConfig(toProbeConfig({ ...defaults, checkApi: '', checkApiBackup: '' }));

    await expect(adapter.probe(target)).resolves.toMatchObject({
      status: 'unknown',
      code: 'NOT_CONFIGURED',
    });
  });

  it('builds the external API adapter as soon as one endpoint is configured', () => {
    const config = toProbeConfig(loadEnvConfig({ CHECK_API: 'https://probe.example/?proxyip={proxyip}' }));

    expect(createProbeAdapterFromConfig(config).name).toBe('external-api');
  });
});
