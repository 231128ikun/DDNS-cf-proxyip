import { describe, expect, it } from 'vitest';
import { createProbeAdapterFromConfig, loadEnvConfig } from '../../src/config/runtime';
import { createDefaultConfig, toProbeConfig } from '../../src/contracts/config';
import { parseProxyTarget } from '../../src/domain/proxy-target';

const target = parseProxyTarget('203.0.113.10:443');
if (!target) throw new Error('test target is invalid');

describe('runtime configuration', () => {
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
