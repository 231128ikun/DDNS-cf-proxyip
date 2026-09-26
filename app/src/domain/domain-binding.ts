import { DEFAULT_POOL_KEY, isUserPoolKey } from '../contracts/pool';
import type { ManagedTarget } from './managed-target';

/**
 * 域名池绑定 key 的唯一格式来源：`域名|模式`。
 * 旧 KV 里可能只有小写域名单键，读取时一并兼容，写入时统一成标准格式。
 */
export function bindingKey(target: ManagedTarget): string {
  return `${normalizeBindingDomain(target.domain)}|${target.mode}`;
}

/** 把任意来源的绑定 key 归一化：域名小写去尾点，模式统一大写；无模式时保留域名单键。 */
export function normalizeBindingKey(key: string): string {
  const [domain, ...rest] = String(key ?? '').split('|');
  const normalizedDomain = normalizeBindingDomain(domain ?? '');
  if (!normalizedDomain) return '';
  const mode = rest.join('|').trim().toUpperCase();
  return mode === 'A' || mode === 'TXT' ? `${normalizedDomain}|${mode}` : normalizedDomain;
}

/** 解析目标实际使用的池 key：标准 key 优先，其次兼容旧的无模式/小写模式 key。 */
export function resolvePoolKey(mapping: Readonly<Record<string, string>>, target: ManagedTarget): string {
  const key = bindingKey(target);
  const mapped = mapping[key] ?? mapping[key.toLowerCase()] ?? mapping[key.slice(0, key.indexOf('|'))];
  return mapped && isUserPoolKey(mapped) ? mapped : DEFAULT_POOL_KEY;
}

/** 显示顺序用的是同一套 key，缺失或未知项忽略，未列出的目标追加在末尾。 */
export function sortByBindingOrder<T extends { readonly key: string }>(
  items: readonly T[],
  order: readonly string[],
): readonly T[] {
  if (order.length === 0) return items;
  const rank = new Map(order.map((key, index) => [key, index]));
  return [...items].sort((left, right) => (rank.get(left.key) ?? order.length) - (rank.get(right.key) ?? order.length));
}

function normalizeBindingDomain(domain: string): string {
  return String(domain ?? '').trim().replace(/\.$/, '').toLowerCase();
}
