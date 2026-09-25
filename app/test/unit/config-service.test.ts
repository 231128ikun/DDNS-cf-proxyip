import { describe, expect, it, vi } from 'vitest';
import { ConfigService } from '../../src/application/config-service';
import { createDefaultConfig, type AppConfig } from '../../src/contracts/config';
import type { ConfigLoadResult, ConfigRepository } from '../../src/ports/config-repository';

const envConfig = configWithCheckApi('https://env.example/?proxyip=');
const storedConfig = configWithCheckApi('https://kv.example/?proxyip=');

describe('ConfigService', () => {
  it('prefers the KV app_config record over environment config', async () => {
    const service = new ConfigService({
      envConfig,
      repository: repository(loaded(storedConfig)),
    });

    await expect(service.resolve()).resolves.toEqual({ config: storedConfig, source: 'kv' });
  });

  it('uses environment config when app_config is missing', async () => {
    const service = new ConfigService({
      envConfig,
      repository: repository({ status: 'missing', source: 'kv' }),
    });

    await expect(service.resolve()).resolves.toEqual({ config: envConfig, source: 'env' });
  });

  it('falls back to environment config and reports invalid app_config', async () => {
    const service = new ConfigService({
      envConfig,
      repository: repository({ status: 'invalid', source: 'kv', message: 'bad config' }),
    });

    await expect(service.resolve()).resolves.toEqual({
      config: envConfig,
      source: 'env',
      notice: 'KV 配置无法读取，已使用环境变量：bad config',
    });
  });

  it('turns repository failures into configuration notices', async () => {
    const service = new ConfigService({
      envConfig,
      repository: {
        load: async () => {
          throw new Error('KV unavailable');
        },
        save: async () => undefined,
      },
    });

    await expect(service.resolve()).resolves.toEqual({
      config: envConfig,
      source: 'env',
      notice: 'KV 配置无法读取，已使用环境变量：KV unavailable',
    });
  });

  it('saves only through the configured repository', async () => {
    const save = vi.fn(async () => undefined);
    const service = new ConfigService({
      envConfig,
      repository: { load: async () => ({ status: 'missing', source: 'kv' }), save },
    });

    await service.save(storedConfig);
    expect(save).toHaveBeenCalledWith(storedConfig);
  });
});

function repository(loadResult: ConfigLoadResult): ConfigRepository {
  return { load: async () => loadResult, save: async () => undefined };
}

function loaded(config: AppConfig): ConfigLoadResult {
  return { status: 'loaded', source: 'kv', config };
}

function configWithCheckApi(checkApi: string): AppConfig {
  return { ...createDefaultConfig(), checkApi, checkApiBackup: '' };
}
