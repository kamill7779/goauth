import { useEffect } from 'react';
import { IconX } from './Icons';

export default function Drawer({ isOpen, onClose, title, children, width = '480px' }: {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  width?: string;
}) {
  useEffect(() => {
    if (!isOpen) return;
    const handleEsc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handleEsc);
    return () => document.removeEventListener('keydown', handleEsc);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[90]">
      <div
        className="absolute inset-0 backdrop-blur-sm animate-[fadeIn_0.2s_ease]"
        style={{ background: 'var(--overlay)' }}
        onClick={onClose}
      />
      <div
        className="absolute right-0 top-0 h-full bg-surface-solid border-l border-line shadow-soft-lg overflow-y-auto"
        style={{ width, animation: 'slideInDrawer 0.35s cubic-bezier(0.16, 1, 0.3, 1)' }}
      >
        <div className="sticky top-0 bg-surface backdrop-blur-sm border-b border-line px-6 py-4 flex items-center justify-between z-10">
          <h2 className="text-base font-semibold text-ink">{title}</h2>
          <button onClick={onClose} className="p-1.5 hover:bg-surface-hover rounded-lg transition-colors text-ink-secondary">
            <IconX size={18} />
          </button>
        </div>
        <div className="p-6">{children}</div>
      </div>
    </div>
  );
}
