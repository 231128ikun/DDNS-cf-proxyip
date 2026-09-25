import {
  DEFAULT_POOL_KEY,
  NUMBERED_POOL_KEY_RE,
  TRASH_POOL_KEY,
  getNumberedPoolKey,
  getPoolFixedName,
  type PoolSummary,
} from '../../src/contracts/pool';
import { parsePoolText } from '../../src/domain/pool-entry';
import type { PoolCatalog } from '../../src/ports/pool-catalog';

/** 仅用于单元测试的内存池目录，行为对齐 KvPoolCatalog 的公开语义。 */
export class MemoryPoolCatalog implements PoolCatalog {
  readonly data = new Map<string, string>();
  readonly names = new Map<string, string>();
  readonly removed: string[] = [];
  readonly order: string[] = [];

  constructor(initial: Readonly<Record<string, string>> = {}) {
    for (const [key, content] of Object.entries(initial)) this.data.set(key, content);
  }

  async list(): Promise<readonly PoolSummary[]> {
    return this.orderedKeys().map((key) => ({
      key,
      name: this.names.get(key) ?? getPoolFixedName(key),
      count: parsePoolText(this.data.get(key) ?? '').filter((line) => line.entry !== null).length,
    }));
  }

  async read(poolKey: string): Promise<string> {
    return this.data.get(poolKey) ?? '';
  }

  async write(poolKey: string, content: string): Promise<void> {
    this.data.set(poolKey, content);
  }

  async create(displayName: string): Promise<PoolSummary> {
    let nextIndex = 1;
    for (const key of this.data.keys()) {
      const match = NUMBERED_POOL_KEY_RE.exec(key);
      if (match) nextIndex = Math.max(nextIndex, Number(match[1]) + 1);
    }
    const key = getNumberedPoolKey(nextIndex);
    this.data.set(key, '');
    if (displayName !== getPoolFixedName(key)) this.names.set(key, displayName);
    return { key, name: displayName, count: 0 };
  }

  async rename(poolKey: string, displayName: string): Promise<void> {
    if (displayName === getPoolFixedName(poolKey)) this.names.delete(poolKey);
    else this.names.set(poolKey, displayName);
  }

  async exists(poolKey: string): Promise<boolean> {
    return poolKey === DEFAULT_POOL_KEY || poolKey === TRASH_POOL_KEY || this.data.has(poolKey);
  }

  async remove(poolKey: string): Promise<void> {
    this.data.delete(poolKey);
    this.names.delete(poolKey);
    const index = this.order.indexOf(poolKey);
    if (index >= 0) this.order.splice(index, 1);
    this.removed.push(poolKey);
  }

  async saveOrder(order: readonly string[]): Promise<void> {
    this.order.splice(0, this.order.length, ...order);
  }

  private orderedKeys(): readonly string[] {
    const keys = new Set([DEFAULT_POOL_KEY, TRASH_POOL_KEY, ...this.data.keys()]);
    const ordered = [...this.order.filter((key) => keys.has(key)), ...keys];
    const unique = [...new Set(ordered)];
    return unique.sort((left, right) => {
      const rank = (key: string) => key === DEFAULT_POOL_KEY ? 0 : key === TRASH_POOL_KEY ? 2 : 1;
      const rankDifference = rank(left) - rank(right);
      if (rankDifference) return rankDifference;
      const leftNumber = NUMBERED_POOL_KEY_RE.exec(left);
      const rightNumber = NUMBERED_POOL_KEY_RE.exec(right);
      if (leftNumber && rightNumber) return Number(leftNumber[1]) - Number(rightNumber[1]);
      return left.localeCompare(right, 'zh-CN', { numeric: true });
    });
  }
}
