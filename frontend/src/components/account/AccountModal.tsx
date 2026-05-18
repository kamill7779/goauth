import { useEffect, type ReactNode } from 'react';
import { IconX } from '../admin/Icons';

interface AccountModalProps {
  open: boolean;
  onClose: () => void;
  children: ReactNode;
  maxWidth?: number;
  title?: string;
}

export default function AccountModal({ open, onClose, children, maxWidth = 480, title }: AccountModalProps) {
  useEffect(() => {
    if (!open) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', handleKey);
      document.body.style.overflow = prev;
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-6"
      style={{ background: 'var(--overlay)', backdropFilter: 'blur(12px) saturate(140%)' }}
      onClick={onClose}
    >
      <div
        className="w-full overflow-y-auto rounded-3xl border border-line bg-surface-solid shadow-soft-lg"
        style={{ maxWidth, maxHeight: '90vh' }}
        onClick={(e) => e.stopPropagation()}
      >
        {title && (
          <div className="flex items-center justify-between border-b border-line px-7 py-5">
            <h3 className="text-lg font-semibold text-ink">{title}</h3>
            <button
              onClick={onClose}
              className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-ink-tertiary transition-colors hover:bg-surface-hover hover:text-ink"
            >
              <IconX size={18} />
            </button>
          </div>
        )}
        <div className={title ? 'px-7 py-6' : 'p-7'}>{children}</div>
      </div>
    </div>
  );
}
