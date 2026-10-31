import type { ManagedTarget } from '../domain/managed-target';
import type { DnsZone } from './dns-repository';

/** `app_config.targets` 中的一条维护目标。 */
export interface MaintenanceTargetConfig {
  readonly target: ManagedTarget;
  /** 指向 zones 的下标；缺失或越界时回退到默认 Cloudflare 凭据。 */
  readonly zoneIndex: number | null;
  readonly enabled: boolean;
}

export interface MaintenanceSourceData {
  /** Cloudflare 区域凭据，按 zoneIndex 引用。 */
  readonly zones: readonly DnsZone[];
  readonly targets: readonly MaintenanceTargetConfig[];
  /** `domain_pool_mapping`：`域名|模式` 或小写域名 → 池 key。 */
  readonly poolMapping: Readonly<Record<string, string>>;
  /** `ip_pool_names`：池 key → 显示名，只用于通知文案。 */
  readonly poolNames: Readonly<Record<string, string>>;
}

/** 维护目标的来源：读取 `app_config` 与池绑定 key。 */
export interface MaintenanceSource {
  load(): Promise<MaintenanceSourceData>;
}