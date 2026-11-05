import type { ProbeStatus } from '../../../src/domain/probe-result';
import type { RequestState } from './request-state';

type State = RequestState<unknown>['status'];
/** 节点失效不代表检测接口异常。 */
export function executionStatus(request: State, items: readonly { readonly status: ProbeStatus; readonly code?: string }[], health: State): 'ready' | 'busy' | 'error' {
  if (request === 'error') return 'error';
  if (request === 'loading') return 'busy';
  if (items.some(item => item.status === 'unknown' && !['CANCELLED', 'NOT_PROBED', 'INVALID_DNS_VALUE'].includes(item.code ?? ''))) return 'error';
  if (request === 'ready' || health === 'ready') return 'ready';
  return health === 'error' ? 'error' : 'busy';
}
