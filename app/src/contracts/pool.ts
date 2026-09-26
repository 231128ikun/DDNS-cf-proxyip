/** IP 池 KV key 约定：面板、维护与存储共用同一套命名。 */

export const POOL_KEY_PREFIX = 'ip_pool_';
export const DEFAULT_POOL_KEY = 'ip_pool_default';
export const TRASH_POOL_KEY = 'ip_pool_trash';
export const POOL_NAMES_KEY = 'ip_pool_names';
export const POOL_ORDER_KEY = 'ip_pool_order';
export const DOMAIN_POOL_MAPPING_KEY = 'domain_pool_mapping';
export const DOMAIN_POOL_ORDER_KEY = 'domain_pool_order';
export const NUMBERED_POOL_KEY_RE = /^ip_pool_(\d{3})$/;
export const MAX_POOL_DISPLAY_NAME_LENGTH = 40;
export const MAX_POOL_RESTORE_ITEMS = 1_000;

export type PoolSaveMode = 'append' | 'replace' | 'remove';

export function isUserPoolKey(value: string): boolean {
  return value === DEFAULT_POOL_KEY || NUMBERED_POOL_KEY_RE.test(value);
}

export function isPoolDataKey(value: string): boolean {
  return isUserPoolKey(value) || value === TRASH_POOL_KEY;
}

export function formatPoolNumber(value: number | string): string {
  return String(value).padStart(3, '0');
}

export function getNumberedPoolKey(value: number | string): string {
  return `${POOL_KEY_PREFIX}${formatPoolNumber(value)}`;
}

export function getPoolFixedName(poolKey: string): string {
  if (poolKey === DEFAULT_POOL_KEY) return '默认池';
  if (poolKey === TRASH_POOL_KEY) return '垃圾桶';
  const numbered = NUMBERED_POOL_KEY_RE.exec(poolKey);
  return numbered ? `池 ${numbered[1]}` : poolKey;
}

export interface PoolSummary {
  readonly key: string;
  readonly name: string;
  readonly count: number;
}

export interface PoolsResponse {
  readonly pools: readonly PoolSummary[];
}

export interface PoolContentResponse {
  readonly key: string;
  readonly content: string;
}

export interface SavePoolRequest {
  readonly content: string;
  readonly mode?: PoolSaveMode;
}

export interface PoolSaveResponse {
  readonly ok: true;
  readonly mode: PoolSaveMode;
  readonly count: number;
  readonly added: number;
  readonly removed: number;
  readonly replaced: number;
}

export interface CreatePoolRequest {
  readonly displayName: string;
}

export interface CreatePoolResponse {
  readonly ok: true;
  readonly key: string;
  readonly displayName: string;
}

export interface RenamePoolRequest {
  readonly displayName: string;
}

export interface SavePoolOrderRequest {
  readonly order: readonly string[];
}

export interface RestoreTrashRequest {
  readonly addresses: readonly string[];
  readonly restoreToSource?: boolean;
  readonly targetPool?: string;
}

export interface RestoreTrashResponse {
  readonly ok: true;
  readonly restored: number;
  readonly restoredByPool: Readonly<Record<string, number>>;
}
