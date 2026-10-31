export interface TrashCandidate {
  readonly entryLine: string;
  readonly reason: string;
  readonly poolKey?: string;
}

export interface PoolRepository {
  load(poolKey: string): Promise<string>;
  save(poolKey: string, content: string): Promise<void>;
  addToTrash(entries: readonly TrashCandidate[]): Promise<void>;
}
