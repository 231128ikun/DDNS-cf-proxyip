import type { PoolCheckItemResponse } from '../../../src/contracts/pool-check';
import { canonicalAddressKey } from '../../../src/domain/pool-entry';
import { readPoolSnapshot, type PoolSnapshot } from '../../../src/domain/pool-snapshot';

export function describeBatch(text: string, groups: ReadonlyMap<number, readonly PoolCheckItemResponse[]>, completed: ReadonlySet<number>) {
  const source = readPoolSnapshot(text);
  return { source: text, items: [...groups.values()].flat(), invalid: source.invalid,
    incomplete: remainingLines(source, completed).filter(line => line.valid).map(line => line.raw) };
}

/** 重复目标复用首次源索引，续检保留所有重复行合并后的有效元数据。 */
export function remainingBatch(
  text: string,
  completed: ReadonlySet<number>,
): { readonly text: string; readonly sourceIndices: readonly number[] } {
  const remaining = remainingLines(readPoolSnapshot(text), completed);
  return {
    text: remaining.map(line => line.raw).join('\n'),
    sourceIndices: remaining.map(line => line.sourceIndex),
  };
}

function remainingLines(snapshot: PoolSnapshot, completed: ReadonlySet<number>) {
  const seen = new Set<string>();
  const remaining: { readonly raw: string; readonly sourceIndex: number; readonly valid: boolean }[] = [];
  for (const [sourceIndex, line] of snapshot.lines.entries()) {
    const key = line.entry ? canonicalAddressKey(line.entry.address) : '';
    const merged = snapshot.entries.get(key);
    if (merged && seen.has(key)) continue;
    if (merged) seen.add(key);
    if (!completed.has(sourceIndex)) remaining.push({ raw: merged?.raw ?? line.raw, sourceIndex, valid: Boolean(merged) });
  }
  return remaining;
}
