import { DEFAULT_POOL_KEY, TRASH_POOL_KEY, type PoolsResponse } from '../../../src/contracts/pool';
import type { RequestState } from './request-state';

interface PoolOption {
  readonly key: string;
  readonly name: string;
  readonly count?: number;
}

export function poolOptions(state: RequestState<PoolsResponse>, currentKey: string): readonly PoolOption[] {
  // 列表已经按保存的池顺序返回；在页面再按名称排序会让“保存排序”失效。
  const options: PoolOption[] = state.status === 'ready'
    ? state.data.pools.map((pool) => ({ key: pool.key, name: pool.name, count: pool.count }))
    : [{ key: DEFAULT_POOL_KEY, name: '默认池' }, { key: TRASH_POOL_KEY, name: '垃圾桶' }];
  if (!options.some((option) => option.key === currentKey)) options.push({ key: currentKey, name: currentKey });
  return options;
}
