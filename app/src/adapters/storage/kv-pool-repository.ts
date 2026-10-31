import { TRASH_POOL_KEY } from '../../contracts/pool';
import { canonicalAddressKey, extractPoolAddressKey, formatPoolEntry, parsePoolEntry } from '../../domain/pool-entry';
import type { PoolRepository, TrashCandidate } from '../../ports/pool-repository';
import { formatBeijingTimestamp } from '../../util/time';

export interface KvPoolRepositoryOptions {
  readonly trashKey?: string;
  readonly maxTrashSize?: number;
  readonly now?: () => Date;
}

export class KvPoolRepository implements PoolRepository {
  private readonly trashKey: string;
  private readonly maxTrashSize: number;
  private readonly now: () => Date;

  constructor(private readonly kv: KVNamespace, options: KvPoolRepositoryOptions = {}) {
    this.trashKey = options.trashKey ?? TRASH_POOL_KEY;
    this.maxTrashSize = options.maxTrashSize ?? 1_000;
    this.now = options.now ?? (() => new Date());
  }

  async load(poolKey: string): Promise<string> {
    return await this.kv.get(poolKey, { type: 'text' }) ?? '';
  }

  async save(poolKey: string, content: string): Promise<void> {
    await this.kv.put(poolKey, content);
  }

  async addToTrash(entries: readonly TrashCandidate[]): Promise<void> {
    if (entries.length === 0) return;
    const existing = (await this.load(this.trashKey)).split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    const seen = new Set(existing.map(extractPoolAddressKey).map(canonicalAddressKey));
    const timestamp = formatBeijingTimestamp(this.now());

    for (const item of entries) {
      const key = canonicalAddressKey(extractPoolAddressKey(item.entryLine));
      if (!key || seen.has(key)) continue;
      const parsed = parsePoolEntry(item.entryLine);
      const cleanEntry = parsed ? formatPoolEntry({ ...parsed, comment: '' }) : item.entryLine.trim();
      if (!cleanEntry) continue;
      existing.push(`${cleanEntry} # ${item.reason} ${timestamp}${item.poolKey ? ` 来自 ${item.poolKey}` : ''}`);
      seen.add(key);
    }

    const limited = this.maxTrashSize > 0 ? existing.slice(-this.maxTrashSize) : [];
    await this.kv.put(this.trashKey, limited.join('\n'));
  }
}
