import type { ComponentChildren } from 'preact';
import { useEffect, useRef } from 'preact/hooks';

interface ModalProps {
  readonly id: string;
  readonly title: string;
  readonly className?: string;
  readonly returnFocusId?: string;
  readonly onClose?: () => void;
  readonly children: ComponentChildren;
}

/** 中断确认和排序共用遮罩、焦点约束与关闭行为。 */
export function Modal({ id, title, className = '', returnFocusId, onClose, children }: ModalProps) {
  const dialog = useRef<HTMLDivElement>(null);
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const element = dialog.current;
    if (!element) return undefined;
    const trigger = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const controls = (): HTMLElement[] => [...element.querySelectorAll<HTMLElement>(
      'button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])',
    )].filter(control => control.getClientRects().length > 0);
    (controls()[0] ?? element).focus();
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === 'Escape' && close.current) {
        event.preventDefault();
        close.current();
      }
      if (event.key !== 'Tab') return;
      const focusable = controls();
      const active = document.activeElement;
      const first = focusable[0];
      const last = focusable.at(-1);
      if (!first || !focusable.includes(active as HTMLElement) || (event.shiftKey ? active === first : active === last)) {
        event.preventDefault();
        (event.shiftKey ? last ?? element : first ?? element).focus();
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = previousOverflow;
      const target = (returnFocusId ? document.getElementById(returnFocusId) : null) ?? trigger;
      if (target?.isConnected) target.focus();
    };
  }, []);
  return (
    <div class="custom-modal-overlay" onClick={event => {
      if (event.target === event.currentTarget) close.current?.();
    }}>
      <div class={`custom-modal ${className}`} ref={dialog} role="dialog" aria-modal="true" aria-labelledby={id} tabIndex={-1}>
        <h2 class="custom-modal-title" id={id}>{title}</h2>
        {children}
      </div>
    </div>
  );
}
