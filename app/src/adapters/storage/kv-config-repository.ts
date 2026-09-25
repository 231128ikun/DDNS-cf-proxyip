import { parseAppConfig, type AppConfig } from '../../contracts/config';
import type { ConfigLoadResult, ConfigRepository } from '../../ports/config-repository';
import { readKvJson } from './kv-json';

export const CONFIG_KEY = 'app_config';

export interface KvConfigRepositoryOptions {
  readonly key?: string;
  readonly cacheTtl?: number;
}

export class KvConfigRepository implements ConfigRepository {
  private readonly key: string;
  private readonly cacheTtl: number;

  constructor(private readonly kv: KVNamespace, options: KvConfigRepositoryOptions = {}) {
    this.key = options.key ?? CONFIG_KEY;
    this.cacheTtl = options.cacheTtl ?? 60;
  }

  async load(previous?: AppConfig): Promise<ConfigLoadResult> {
    const raw = await readKvJson(this.kv, this.key, this.cacheTtl);
    if (raw.status === 'missing') return { status: 'missing', source: 'kv' };
    if (raw.status === 'invalid') return { status: 'invalid', source: 'kv', message: raw.message };

    const parsed = parseAppConfig(raw.value, previous);
    if (!parsed.ok) return { status: 'invalid', source: 'kv', message: parsed.message };
    return { status: 'loaded', source: 'kv', config: parsed.value };
  }

  async save(config: AppConfig): Promise<void> {
    const parsed = parseAppConfig(config);
    if (!parsed.ok) throw new Error(parsed.message);
    await this.kv.put(this.key, JSON.stringify(parsed.value));
  }
}
