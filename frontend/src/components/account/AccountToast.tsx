import { useEffect } from 'react';
import {
  IconCheckCircle,
  IconAlertTriangle,
  IconInfo,
} from '../admin/Icons';

export type ToastType = 'success' | 'error' | 'info';

export interface ToastItem {
  id: string;
  message: string;
  type: ToastType;
}

interface AccountToastProps {
  toast: ToastItem | null;
  onDismiss: () => void;
}

const config: Record<ToastType, { icon: typeof IconCheckCircle; colorClass: string }> = {
  success: { icon: IconCheckCircle, colorClass: 'text-ok' },
  error: { icon: IconAlertTriangle, colorClass: 'text-danger' },
  info: { icon: IconInfo, colorClass: 'text-brand' },
};

export default function AccountToast({ toast, onDismiss }: AccountToastProps) {
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => onDismiss(), 3800);
    return () => clearTimeout(t);
  }, [toast, onDismiss]);

  if (!toast) return null;

  const { icon: Icon, colorClass } = config[toast.type];

  return (
    <div
      className="fixed bottom-6 left-1/2 z-[100] flex -translate-x-1/2 items-center gap-3 rounded-2xl px-5 py-3 text-sm font-medium text-ink-inverse shadow-soft-lg"
      style={{
        background: 'var(--ink)',
        animation: 'toastIn 0.5s cubic-bezier(0.32, 0.72, 0, 1) both',
      }}
    >
      <span className={colorClass}><Icon size={18} /></span>
      <span>{toast.message}</span>
    </div>
  );
}
