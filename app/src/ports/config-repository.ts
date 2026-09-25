import type { AppConfig } from '../contracts/config';

export type ConfigRecordSource = 'kv';

export type ConfigLoadResult =
  | { readonly status: 'missing'; readonly source: ConfigRecordSource }
  | { readonly status: 'loaded'; readonly source: ConfigRecordSource; readonly config: AppConfig }
  | { readonly status: 'invalid'; readonly source: ConfigRecordSource; readonly message: string };

export interface ConfigRepository {
  load(previous?: AppConfig): Promise<ConfigLoadResult>;
  save(config: AppConfig): Promise<void>;
}
