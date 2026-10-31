import type { TargetMode } from '../domain/managed-target';

export interface DomainBindingItem {
  readonly key: string;
  readonly domain: string;
  readonly mode: TargetMode;
  readonly poolKey: string;
  readonly poolName: string;
  readonly enabled: boolean;
}

export interface DomainBindingsResponse {
  readonly items: readonly DomainBindingItem[];
}

export interface SaveDomainBindingsRequest {
  readonly mapping: Readonly<Record<string, string>>;
}

/** 域名池绑定的显示顺序；只影响面板排序，不影响维护执行顺序。 */
export interface SaveDomainBindingOrderRequest {
  readonly order: readonly string[];
}

export interface MaintenanceRunResult {
  readonly domain: string;
  readonly mode: TargetMode;
  readonly poolKey: string;
  readonly poolName: string;
  readonly dnsUpdated: boolean;
  readonly added: number;
  readonly deleted: number;
  readonly probeErrors: number;
  readonly error: string | null;
}

export interface MaintenanceRunResponse {
  readonly ok: true;
  readonly changed: boolean;
  readonly insufficient: boolean;
  readonly errors: readonly string[];
  readonly probeErrors: number;
  readonly results: readonly MaintenanceRunResult[];
}