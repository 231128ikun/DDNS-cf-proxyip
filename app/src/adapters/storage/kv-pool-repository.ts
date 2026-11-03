import { TRASH_POOL_KEY } from '../../contracts/pool';
import { planTrashAppend } from '../../domain/trash';
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
    const plan = planTrashAppend(await this.load(this.trashKey), entries, {
      timestamp: formatBeijingTimestamp(this.now()), maxSize: this.maxTrashSize,
    });
    await this.kv.put(this.trashKey, plan.content);
  }
}
