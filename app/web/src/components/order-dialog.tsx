import { useRef, useState } from 'preact/hooks';
import { errorMessage } from '../api/errors';
import { Modal } from './modal';

interface OrderItem {
  readonly key: string;
  readonly name: string;
  readonly detail: string;
}

export interface OrderRequest {
  readonly kind: 'pools' | 'bindings';
  readonly items: readonly OrderItem[];
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
    <Modal id={`${prefix}-title`} title={kind === 'pools' ? '自定义池排序' : '自定义绑定池排序'}
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
