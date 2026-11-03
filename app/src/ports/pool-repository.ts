import type { TrashCandidate } from '../domain/trash';
export type { TrashCandidate } from '../domain/trash';

export interface PoolRepository {
  load(poolKey: string): Promise<string>;
  save(poolKey: string, content: string): Promise<void>;
  addToTrash(entries: readonly TrashCandidate[]): Promise<void>;
}
