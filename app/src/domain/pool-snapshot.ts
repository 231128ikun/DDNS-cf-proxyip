import { canonicalAddressKey, formatPoolEntry, parsePoolAddress, parsePoolText, type PoolEntry } from './pool-entry';

export interface PoolSnapshotItem {
  readonly raw: string;
  readonly entry: PoolEntry;
}

export interface PoolSnapshot {
  readonly text: string;
  readonly entries: ReadonlyMap<string, PoolSnapshotItem>;
}

/** 池文本的统一读取边界；保留原文快照，规划阶段不访问存储。 */
export function readPoolSnapshot(text: string): PoolSnapshot {
  const entries = new Map<string, PoolSnapshotItem>();
  for (const line of parsePoolText(text)) {
    if (!line.entry || !parsePoolAddress(line.entry)) continue;
    const key = canonicalAddressKey(line.entry.address);
    if (key) entries.set(key, { raw: line.raw, entry: line.entry });
  }
  return { text, entries };
}

export function snapshotEntries(snapshot: PoolSnapshot): Map<string, PoolEntry> {
  return new Map([...snapshot.entries].map(([key, item]) => [key, item.entry]));
}

export function serializePoolEntries(entries: ReadonlyMap<string, PoolEntry>): string {
  return [...entries.values()].map(formatPoolEntry).join('\n');
}
