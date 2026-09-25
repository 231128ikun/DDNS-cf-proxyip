import {
  DEFAULT_POOL_KEY,
  DOMAIN_POOL_MAPPING_KEY,
  NUMBERED_POOL_KEY_RE,
  POOL_KEY_PREFIX,
  POOL_NAMES_KEY,
  POOL_ORDER_KEY,
  TRASH_POOL_KEY,
  getNumberedPoolKey,
  getPoolFixedName,
  isPoolDataKey,
} from '../../contracts/pool';
import { parsePoolText } from '../../domain/pool-entry';
import type { PoolSummary } from '../../contracts/pool';
import type { PoolCatalog } from '../../ports/pool-catalog';
import { readKvStringRecord } from './kv-json';
import { mapWithConcurrency } from '../../util/concurrency';

/** 基于单个 KV 命名空间的 IP 池目录：池列表、内容读写与显示名。 */
export class KvPoolCatalog implements PoolCatalog {
  constructor(private readonly kv: KVNamespace) {}

  async list(): Promise<readonly PoolSummary[]> {
    const [names, order, keys] = await Promise.all([
      this.readNames(),
      this.readOrder(),
      this.listPoolKeys(),
    ]);
    const normalizedOrder = normalizeOrder(order, keys);
    const summaries = await mapWithConcurrency(normalizedOrder, 4, async (key) => {
      const content = await this.read(key);
      return {
        key,
        name: names[key] ?? getPoolFixedName(key),
        count: parsePoolText(content).filter((line) => line.entry !== null).length,
      };
    });
    return summaries;
  }

  async read(poolKey: string): Promise<string> {
    return await this.kv.get(poolKey, { type: 'text' }) ?? '';
  }

  async write(poolKey: string, content: string): Promise<void> {
    await this.kv.put(poolKey, content);
  }

  async create(displayName: string): Promise<PoolSummary> {
    const [keys, names, savedOrder] = await Promise.all([
      this.listPoolKeys(),
      this.readNames(),
      this.readOrder(),
    ]);
    let nextIndex = 1;
    for (const key of keys) {
      const match = NUMBERED_POOL_KEY_RE.exec(key);
      if (match) nextIndex = Math.max(nextIndex, Number(match[1]) + 1);
    }
    if (nextIndex > 999) throw new Error('编号 IP 池数量已达上限');
    const poolKey = getNumberedPoolKey(nextIndex);

    await this.kv.put(poolKey, '');
    if (displayName !== getPoolFixedName(poolKey)) {
      await this.writeNames({ ...names, [poolKey]: displayName });
    }
    if (savedOrder) await this.writeOrder(normalizeOrder([...savedOrder, poolKey], [...keys, poolKey]));
    return { key: poolKey, name: displayName, count: 0 };
  }

  async rename(poolKey: string, displayName: string): Promise<void> {
    const names = await this.readNames();
    if (displayName === getPoolFixedName(poolKey)) delete names[poolKey];
    else names[poolKey] = displayName;
    await this.writeNames(names);
  }

  async exists(poolKey: string): Promise<boolean> {
    if (poolKey === DEFAULT_POOL_KEY || poolKey === TRASH_POOL_KEY) return true;
    return await this.kv.get(poolKey, { type: 'text' }) !== null;
  }

  async remove(poolKey: string): Promise<void> {
    await this.kv.delete(poolKey);

    const [savedOrder, names, mapping] = await Promise.all([
      this.readOrder(),
      this.readNames(),
      this.readMapping(),
    ]);

    if (savedOrder?.includes(poolKey)) {
      await this.writeOrder(savedOrder.filter((key) => key !== poolKey));
    }
    if (Object.hasOwn(names, poolKey)) {
      delete names[poolKey];
      await this.writeNames(names);
    }

    let mappingChanged = false;
    for (const [domain, boundPool] of Object.entries(mapping)) {
      if (boundPool === poolKey) {
        mapping[domain] = DEFAULT_POOL_KEY;
        mappingChanged = true;
      }
    }
    if (mappingChanged) await this.kv.put(DOMAIN_POOL_MAPPING_KEY, JSON.stringify(mapping));
  }

  async saveOrder(order: readonly string[]): Promise<void> {
    const keys = await this.listPoolKeys();
    await this.writeOrder(normalizeOrder(order, keys));
  }

  private async readNames(): Promise<Record<string, string>> {
    return await readKvStringRecord(this.kv, POOL_NAMES_KEY);
  }

  private async readOrder(): Promise<readonly string[] | null> {
    const raw = await this.kv.get(POOL_ORDER_KEY, { type: 'json' }).catch(() => null);
    return Array.isArray(raw) ? raw.filter((value): value is string => typeof value === 'string') : null;
  }

  private async readMapping(): Promise<Record<string, string>> {
    return await readKvStringRecord(this.kv, DOMAIN_POOL_MAPPING_KEY);
  }

  private async writeNames(names: Record<string, string>): Promise<void> {
    await this.kv.put(POOL_NAMES_KEY, JSON.stringify(names));
  }

  private async writeOrder(order: readonly string[]): Promise<void> {
    await this.kv.put(POOL_ORDER_KEY, JSON.stringify(order));
  }

  private async listPoolKeys(): Promise<readonly string[]> {
    const keys = new Set<string>([DEFAULT_POOL_KEY, TRASH_POOL_KEY]);
    let cursor: string | undefined;
    do {
      const page = await this.kv.list({ prefix: POOL_KEY_PREFIX, ...(cursor ? { cursor } : {}) });
      for (const key of page.keys) if (isPoolDataKey(key.name)) keys.add(key.name);
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);
    return [...keys];
  }
}

function normalizeOrder(saved: readonly string[] | null, actualKeys: readonly string[]): readonly string[] {
  const actual = [...new Set(actualKeys.filter(isPoolDataKey))];
  const actualSet = new Set(actual);
  const fallback = [...actual].sort(comparePoolKeys);
  const normalized: string[] = [];
  for (const key of saved ?? fallback) {
    if (actualSet.has(key) && !normalized.includes(key)) normalized.push(key);
  }
  for (const key of fallback) if (!normalized.includes(key)) normalized.push(key);

  const middle = normalized.filter((key) => key !== DEFAULT_POOL_KEY && key !== TRASH_POOL_KEY);
  return [
    ...(actualSet.has(DEFAULT_POOL_KEY) ? [DEFAULT_POOL_KEY] : []),
    ...middle,
    ...(actualSet.has(TRASH_POOL_KEY) ? [TRASH_POOL_KEY] : []),
  ];
}

function comparePoolKeys(left: string, right: string): number {
  const rank = (key: string): number => key === DEFAULT_POOL_KEY ? 0 : key === TRASH_POOL_KEY ? 2 : 1;
  const difference = rank(left) - rank(right);
  if (difference !== 0) return difference;
  const leftNumber = NUMBERED_POOL_KEY_RE.exec(left);
  const rightNumber = NUMBERED_POOL_KEY_RE.exec(right);
  if (leftNumber && rightNumber) return Number(leftNumber[1]) - Number(rightNumber[1]);
  return left.localeCompare(right, 'zh-CN', { numeric: true });
}
