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

/** 原生模态约束焦点和背景交互，关闭后回到触发控件。 */
export function Modal({ id, title, className = '', returnFocusId, onClose, children }: ModalProps) {
  const dialog = useRef<HTMLDialogElement>(null);
  const backdropPressed = useRef(false);
  useEffect(() => {
    const element = dialog.current;
    if (!element) return undefined;
    const previousOverflow = document.body.style.overflow;
    const trigger = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    document.body.style.overflow = 'hidden';
    element.showModal();
    return () => {
      element.close();
      document.body.style.overflow = previousOverflow;
      const target = returnFocusId ? document.getElementById(returnFocusId) : trigger;
      if (target?.isConnected) target.focus({ preventScroll: true });
    };
  }, []);
  return (
    <dialog class="custom-modal-overlay" ref={dialog} role="dialog" aria-modal="true" aria-labelledby={id}
      onCancel={event => { event.preventDefault(); onClose?.(); }}
      onPointerDown={event => { backdropPressed.current = event.target === event.currentTarget; }}
      onPointerUp={event => {
        backdropPressed.current &&= document.elementFromPoint(event.clientX, event.clientY) === event.currentTarget;
      }}
      onPointerCancel={() => { backdropPressed.current = false; }}
      onClick={event => {
        const close = backdropPressed.current && event.target === event.currentTarget;
        backdropPressed.current = false;
        if (close) onClose?.();
      }}>
      <div class={`custom-modal ${className}`} tabIndex={-1}>
        <h2 class="custom-modal-title" id={id}>{title}</h2>
        {children}
      </div>
    </dialog>
  );
}
