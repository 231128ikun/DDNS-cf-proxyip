import { isUserPoolKey } from '../contracts/pool';
import { canonicalAddressKey, extractPoolAddressKey, formatPoolEntry, parsePoolEntry } from './pool-entry';

export interface TrashCandidate {
  readonly entryLine: string;
  readonly reason: string;
  readonly poolKey?: string;
}

const SOURCE_MARKER = ' 来自 ';

export function sourcePoolFromTrash(line: string): string | null {
  const index = line.lastIndexOf(SOURCE_MARKER);
  if (index < 0) return null;
  const key = line.slice(index + SOURCE_MARKER.length).trim();
  return isUserPoolKey(key) ? key : null;
}

/** 入桶的去重、截断和来源格式只有这一份纯规则。 */
export function planTrashAppend(text: string, candidates: readonly TrashCandidate[], options: { readonly timestamp: string; readonly maxSize: number }): { readonly content: string; readonly changed: boolean } {
  const lines = text.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  const seen = new Set(lines.map(extractPoolAddressKey).map(canonicalAddressKey));
  for (const candidate of candidates) {
    const key = canonicalAddressKey(extractPoolAddressKey(candidate.entryLine));
    if (!key || seen.has(key)) continue;
    const entry = parsePoolEntry(candidate.entryLine);
    const clean = entry ? formatPoolEntry({ ...entry, comment: '' }) : candidate.entryLine.trim();
    if (!clean) continue;
    lines.push(`${clean} # ${candidate.reason} ${options.timestamp}${candidate.poolKey ? `${SOURCE_MARKER}${candidate.poolKey}` : ''}`);
    seen.add(key);
  }
  const content = (options.maxSize > 0 ? lines.slice(-options.maxSize) : []).join('\n');
  return { content, changed: content !== text };
}
