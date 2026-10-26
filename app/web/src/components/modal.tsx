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

/** 中断确认和排序共用原生模态行为，浏览器约束焦点和背景交互。 */
export function Modal({ id, title, className = '', returnFocusId, onClose, children }: ModalProps) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current;
    if (!element) return undefined;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    element.showModal();
    return () => {
      element.close();
      document.body.style.overflow = previousOverflow;
      if (returnFocusId) document.getElementById(returnFocusId)?.focus();
    };
  }, []);
  return (
    <dialog class="custom-modal-overlay" ref={dialog} role="dialog" aria-modal="true" aria-labelledby={id}
      onCancel={event => { event.preventDefault(); onClose?.(); }} onClick={event => {
      if (event.target === event.currentTarget) onClose?.();
    }}>
      <div class={`custom-modal ${className}`} tabIndex={-1}>
        <h2 class="custom-modal-title" id={id}>{title}</h2>
        {children}
      </div>
    </dialog>
  );
}
