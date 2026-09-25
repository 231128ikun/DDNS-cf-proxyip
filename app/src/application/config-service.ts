import type { AppConfig } from '../contracts/config';
import type {
  ConfigLoadResult,
  ConfigRecordSource,
  ConfigRepository,
} from '../ports/config-repository';

export type EffectiveConfigSource = 'kv' | 'env';

export interface ResolvedConfig {
  readonly config: AppConfig;
  readonly source: EffectiveConfigSource;
  readonly notice?: string;
}

export interface ConfigServiceOptions {
  readonly envConfig: AppConfig;
  readonly repository?: ConfigRepository;
}

export class ConfigService {
  constructor(private readonly options: ConfigServiceOptions) {}

  async resolve(): Promise<ResolvedConfig> {
    const result = this.options.repository
      ? await loadSafely(() => this.options.repository!.load(this.options.envConfig))
      : missing();
    if (result.status === 'loaded') return { config: result.config, source: 'kv' };

    return {
      config: this.options.envConfig,
      source: 'env',
      ...(result.status === 'invalid' ? { notice: `KV 配置无法读取，已使用环境变量：${result.message}` } : {}),
    };
  }

  async save(config: AppConfig): Promise<void> {
    if (!this.options.repository) throw new Error('config repository is not configured');
    await this.options.repository.save(config);
  }
}

function missing(): ConfigLoadResult {
  return { status: 'missing', source: 'kv' };
}

async function loadSafely(
  load: () => Promise<ConfigLoadResult>,
): Promise<ConfigLoadResult> {
  try {
    return await load();
  } catch (error) {
    return {
      status: 'invalid',
      source: 'kv' as ConfigRecordSource,
      message: error instanceof Error ? error.message : '读取配置失败',
    };
  }
}
