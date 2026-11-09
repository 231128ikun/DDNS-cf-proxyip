import { TRASH_POOL_KEY, type PoolSaveMode } from '../contracts/pool';
import { formatPoolEntry, mergePoolEntry, type PoolEntry } from './pool-entry';
import { serializePoolEntries, snapshotEntries, type PoolSnapshot } from './pool-snapshot';
import type { ProbeResult } from './probe-result';
import type { TrashCandidate } from './trash';

export interface PoolContentWrite {
  readonly poolKey: string;
  readonly before: string;
  readonly after: string;
}

export function planPoolSave(poolKey: string, before: PoolSnapshot, incoming: PoolSnapshot, mode: PoolSaveMode) {
  const existing = snapshotEntries(before);
  const next = mode === 'replace' ? snapshotEntries(incoming) : new Map(existing);
  if (mode === 'append') {
    for (const [key, item] of incoming.entries) {
      const previous = next.get(key);
      next.set(key, previous ? mergePoolEntry(previous, item.entry) : item.entry);
    }
  } else if (mode === 'remove') {
    for (const key of incoming.entries.keys()) next.delete(key);
  }
  const content = serializePoolEntries(next, mode === 'replace' ? incoming : before);
  return {
    write: { poolKey, before: before.text, after: content } satisfies PoolContentWrite,
    changed: content !== before.text,
    summary: { mode, count: next.size, added: mode === 'replace' ? next.size : mode === 'append' ? next.size - existing.size : 0,
      removed: mode === 'remove' ? existing.size - next.size : 0, replaced: mode === 'replace' ? existing.size : 0 },
  };
}

/** 来源选择由用例解析；规划阶段只计算目标写入与最后的垃圾桶清理。 */
export function planPoolRestore(trash: PoolSnapshot, destinations: ReadonlyMap<string, PoolSnapshot>, assignments: ReadonlyMap<string, string>) {
  const remaining = snapshotEntries(trash);
  const targets = new Map<string, Map<string, PoolEntry>>();
  const restoredByPool: Record<string, number> = {};
  let restored = 0;
  let trashChanged = false;
  for (const [key, poolKey] of assignments) {
    const item = trash.entries.get(key);
    if (!item) continue;
    const destination = destinations.get(poolKey);
    if (!destination) throw new Error('恢复目标池快照缺失');
    remaining.delete(key);
    trashChanged = true;
    let entries = targets.get(poolKey);
    if (!entries) { entries = snapshotEntries(destination); targets.set(poolKey, entries); }
    const current = entries.get(key);
    if (current) {
      // 旧垃圾桶只能补齐缺失字段，不能覆盖目标池更新的元数据或用户备注。
      entries.set(key, mergePoolEntry({ ...item.entry, comment: '' }, current));
      continue;
    }
    entries.set(key, { ...item.entry, comment: '' });
    restored++;
    restoredByPool[poolKey] = (restoredByPool[poolKey] ?? 0) + 1;
  }
  const writes: PoolContentWrite[] = [];
  for (const [poolKey, entries] of targets) {
    const before = destinations.get(poolKey)!.text;
    const after = serializePoolEntries(entries, destinations.get(poolKey));
    if (after !== before) writes.push({ poolKey, before, after });
  }
  if (trashChanged) writes.push({ poolKey: TRASH_POOL_KEY, before: trash.text, after: serializePoolEntries(remaining, trash) });
  return { writes, summary: { restored, restoredByPool } };
}

interface PoolInspection {
  readonly total: number;
  readonly unknown: number;
  readonly invalid: readonly string[];
  readonly items: readonly { readonly address: string; readonly entry: PoolEntry; readonly result: ProbeResult }[];
}

export function planPoolCleaning(poolKey: string, report: PoolInspection, source?: PoolSnapshot) {
  const unknown = report.unknown + report.invalid.length;
  const skipped = report.invalid.length > 0;
  const alive = skipped ? [] : report.items.filter(item => item.result.status === 'alive');
  const dead = skipped ? [] : report.items.filter(item => item.result.status === 'dead');
  const retained = skipped ? [] : report.items.filter(item => item.result.status !== 'dead');
  const inTrash = poolKey === TRASH_POOL_KEY;
  const trash: TrashCandidate[] = inTrash ? [] : dead.map(item => ({ entryLine: formatPoolEntry(item.entry), reason: '洗库失效', poolKey }));
  return {
    summary: { checked: report.total, kept: inTrash ? 0 : retained.length, trashed: trash.length, unknown, skipped },
    restoreAddresses: inTrash ? alive.map(item => item.address) : [],
    nextText: source && !alive.length && !dead.length ? source.text
      : serializePoolEntries(new Map(retained.map(item => [item.address, item.entry])), source),
    trash,
  };
}
