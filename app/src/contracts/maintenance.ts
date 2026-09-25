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