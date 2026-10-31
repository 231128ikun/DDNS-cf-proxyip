import { useRef, useState } from 'preact/hooks';
import { errorMessage } from '../api/errors';
import type { ApiClient } from '../api/client';
import { DEFAULT_POOL_KEY, TRASH_POOL_KEY, NUMBERED_POOL_KEY_RE, getPoolFixedName, type PoolsResponse } from '../../../src/contracts/pool';
import type { DomainBindingsResponse } from '../../../src/contracts/maintenance';
import { sortByKeyOrder } from '../../../src/util/key-order';
import { Modal } from './modal';
import { iconText } from './icon';

interface OrderItem {
  readonly key: string;
  readonly name: string;
  readonly detail: string;
}

export interface OrderRequest {
  readonly kind: 'pools' | 'bindings';
  readonly items: readonly OrderItem[];
}

export function createOrderRequest(kind: OrderRequest['kind'], pools: PoolsResponse | null, bindings: DomainBindingsResponse | null): OrderRequest {
  const items = kind === 'pools'
    ? (pools?.pools ?? []).filter(pool => NUMBERED_POOL_KEY_RE.test(pool.key))
      .map(pool => ({ key: pool.key, name: pool.name, detail: getPoolFixedName(pool.key) }))
    : (bindings?.items ?? []).map(item => ({ key: item.key, name: item.domain, detail: item.mode === 'TXT' ? 'TXT' : 'A/AAAA' }));
  if (items.length < 2) throw new Error(kind === 'pools' ? '至少需要两个自定义池才能排序' : '至少需要两个管理域名才能排序');
  return { kind, items };
}

interface OrderSaveContext {
  readonly client: ApiClient;
  readonly patchPools: (change: (current: PoolsResponse) => PoolsResponse) => void;
  readonly patchBindings: (change: (current: DomainBindingsResponse) => DomainBindingsResponse) => void;
  readonly refreshPools: () => Promise<boolean>;
  readonly refreshBindings: () => Promise<boolean>;
  readonly notify: (message: string, type: 'success' | 'error') => void;
}

/** 页面提供统一客户端和共享资源；排序的保存流程随弹窗按需加载。 */
export async function saveOrder(kind: OrderRequest['kind'], order: readonly string[], context: OrderSaveContext): Promise<void> {
  const poolOrder = kind === 'pools';
  const savedOrder = poolOrder ? [DEFAULT_POOL_KEY, ...order, TRASH_POOL_KEY] : order;
  const { client, patchPools, patchBindings, refreshPools, refreshBindings, notify } = context;
  await (poolOrder ? client.savePoolOrder(savedOrder) : client.saveDomainBindingOrder(savedOrder));
  if (poolOrder) patchPools(current => ({ pools: sortByKeyOrder(current.pools, savedOrder) }));
  else patchBindings(current => ({ items: sortByKeyOrder(current.items, savedOrder) }));
  const refreshed = await (poolOrder ? refreshPools() : refreshBindings());
  notify(`${poolOrder ? '池排序' : '域名池绑定顺序'}已保存${refreshed ? '' : '，刷新失败，请重试读取'}`, refreshed ? 'success' : 'error');
}

interface OrderDialogProps extends OrderRequest {
  readonly onSave: (order: readonly string[]) => Promise<void>;
  readonly onClose: () => void;
}

/** 弹窗只编辑顺序草稿；请求和已保存资源仍由页面统一管理。 */
export function OrderDialog({ kind, items, onSave, onClose }: OrderDialogProps) {
  const [order, setOrder] = useState(() => [...items]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const submitting = useRef(false);
  const prefix = kind === 'pools' ? 'pool-order' : 'domain-pool-order';
  const close = (): void => { if (!submitting.current) onClose(); };
  const move = (index: number, delta: number): void => {
    if (submitting.current) return;
    const target = index + delta;
    if (target < 0 || target >= order.length) return;
    setOrder(current => {
      const next = [...current];
      [next[index], next[target]] = [next[target]!, next[index]!];
      return next;
    });
  };
  const save = async (): Promise<void> => {
    if (submitting.current) return;
    submitting.current = true;
    setSaving(true);
    setError('');
    try {
      await onSave(order.map(item => item.key));
      onClose();
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      submitting.current = false;
      setSaving(false);
    }
  };
  return (
    <Modal id={`${prefix}-title`} title={`${iconText('sort')} ${kind === 'pools' ? '自定义池排序' : '自定义绑定池排序'}`}
      className="pool-order-modal" onClose={close} returnFocusId={kind === 'pools' ? 'pool-action-trigger' : 'domain-order-trigger'}>
      <p class="pool-order-hint">{kind === 'pools'
        ? '默认池固定在最前，垃圾桶固定在最后。使用箭头调整自定义池顺序。'
        : '调整域名池绑定区域中管理域名的显示顺序，不会改变维护执行顺序。'}</p>
      <div class="pool-order-list" id={`${prefix}-list`}>
        {order.map((item, index) => (
          <div class="pool-order-item" key={item.key} data-pool-key={kind === 'pools' ? item.key : undefined}>
            <span class="pool-order-index">{index + 1}</span>
            <span class="pool-order-name"><strong title={item.name}>{item.name}</strong><small>{item.detail}</small></span>
            <span class="pool-order-actions">
              <button class="order-move-btn" type="button" data-action="up" data-index={index}
                title="上移" aria-label={`上移 ${item.name}`} disabled={saving || index === 0} onClick={() => move(index, -1)}>↑</button>
              <button class="order-move-btn" type="button" data-action="down" data-index={index}
                title="下移" aria-label={`下移 ${item.name}`} disabled={saving || index === order.length - 1} onClick={() => move(index, 1)}>↓</button>
            </span>
          </div>
        ))}
      </div>
      {error && <p class="pool-order-error text-danger" role="alert">{error}</p>}
      <div class="custom-modal-buttons">
        <button class="btn-abandon" type="button" id={`${prefix}-cancel`} disabled={saving} onClick={close}>取消</button>
        <button class="btn-continue" type="button" id={`${prefix}-save`} disabled={saving} onClick={() => void save()}>{saving ? '保存中…' : '保存排序'}</button>
      </div>
    </Modal>
  );
}
