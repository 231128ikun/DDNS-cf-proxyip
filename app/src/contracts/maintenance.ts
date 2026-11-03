import type { NotifyResult } from './notification';
import type { ProbeStatus } from '../domain/probe-result';
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

export interface MaintenanceDnsState {
  readonly before: readonly string[];
  readonly after: readonly string[];
  readonly added: readonly string[];
  readonly removed: readonly string[];
}

export interface MaintenanceCandidateStats {
  readonly total: number;
  readonly checked: number;
  readonly unknown: number;
  readonly remaining: number;
  readonly sourceCount?: number;
}

export interface MaintenanceAddressCheck {
  readonly value: string;
  readonly address: string;
  readonly status: ProbeStatus;
  readonly matchesTarget: boolean;
  readonly details: string;
  readonly code?: string;
  readonly message?: string;
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
  readonly errors?: readonly string[];
  readonly dns?: MaintenanceDnsState;
  readonly activeCount?: number;
  readonly minActive?: number;
  readonly port?: number;
  readonly checks?: readonly MaintenanceAddressCheck[];
  readonly candidates?: MaintenanceCandidateStats;
  readonly candidateErrors?: readonly { readonly code: string; readonly message: string; readonly count: number }[];
  readonly archived?: number;
  readonly lines?: readonly string[];
}

export interface MaintenanceRunResponse {
  readonly ok: true;
  readonly changed: boolean;
  readonly insufficient: boolean;
  readonly errors: readonly string[];
  readonly probeErrors: number;
  readonly results: readonly MaintenanceRunResult[];
  readonly notification?: NotifyResult | null;
  readonly notificationMessage?: string;
  readonly message?: string;
  readonly completed?: boolean;
}