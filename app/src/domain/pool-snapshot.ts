import { canonicalAddressKey, formatPoolEntry, mergePoolEntry, parsePoolAddress, parsePoolText, type PoolEntry, type PoolLine } from './pool-entry';

export interface PoolSnapshotItem {
  readonly raw: string;
  readonly entry: PoolEntry;
  readonly sourceIndex: number;
}

export interface PoolSnapshot {
  readonly text: string;
  readonly entries: ReadonlyMap<string, PoolSnapshotItem>;
  readonly lines: readonly PoolLine[];
  readonly invalid: readonly string[];
}

/** 池文本的统一读取边界；重复地址合并有效字段，未知行保留以便校验或无损写回。 */
export function readPoolSnapshot(text: string): PoolSnapshot {
  const entries = new Map<string, PoolSnapshotItem>();
  const lines = parsePoolText(text);
  const invalid: string[] = [];
  for (const [sourceIndex, line] of lines.entries()) {
    const target = line.entry ? parsePoolAddress(line.entry) : null;
    if (!line.entry || !target) { if (!line.raw.startsWith('#')) invalid.push(line.raw); continue; }
    const previous = entries.get(target.key);
    const entry = previous ? mergePoolEntry(previous.entry, line.entry) : line.entry;
    entries.set(target.key, { raw: previous ? formatPoolEntry(entry) : line.raw, entry,
      sourceIndex: previous?.sourceIndex ?? sourceIndex });
  }
  return { text, entries, lines, invalid };
}

export function snapshotEntries(snapshot: PoolSnapshot): Map<string, PoolEntry> {
  return new Map([...snapshot.entries].map(([key, item]) => [key, item.entry]));
}

/** 有来源快照时保留注释和未知行的位置；重复地址只序列化一次。 */
export function serializePoolEntries(entries: ReadonlyMap<string, PoolEntry>, source?: PoolSnapshot): string {
  const output: string[] = [];
  const emitted = new Set<string>();
  for (const line of source?.lines ?? []) {
    const key = line.entry ? canonicalAddressKey(line.entry.address) : '';
    if (!key || !source?.entries.has(key)) { output.push(line.raw); continue; }
    if (emitted.has(key)) continue;
    emitted.add(key);
    const entry = entries.get(key);
    if (entry) output.push(formatPoolEntry(entry));
  }
  for (const [key, entry] of entries) if (!emitted.has(key)) output.push(formatPoolEntry(entry));
  return output.join('\n');
}
