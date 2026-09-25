import type { PoolSummary } from '../contracts/pool';

/**
 * 面向管理面板的 IP 池目录。
 * 与维护流程使用的 `PoolRepository` 分开，避免维护侧被迫实现用不到的读写能力。
 */
export interface PoolCatalog {
  list(): Promise<readonly PoolSummary[]>;
  read(poolKey: string): Promise<string>;
  write(poolKey: string, content: string): Promise<void>;
  create(displayName: string): Promise<PoolSummary>;
  rename(poolKey: string, displayName: string): Promise<void>;
  exists(poolKey: string): Promise<boolean>;
  remove(poolKey: string): Promise<void>;
  saveOrder(order: readonly string[]): Promise<void>;
}
