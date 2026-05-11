import { useEffect } from 'react';

type ToastType = 'success' | 'error' | 'info';

const TOAST_STYLES: Record<ToastType, { background: string; color: string; border: string }> = {
  success: { background: 'var(--ink)', color: 'var(--ink-inverse)', border: 'transparent' },
  error: { background: 'var(--error)', color: '#FFFFFF', border: 'transparent' },
  info: { background: 'var(--accent)', color: '#FFFFFF', border: 'transparent' },
};

export default function Toast({ message, type = 'success', onClose }: { message: string; type?: ToastType; onClose: () => void }) {
  useEffect(() => {
    const timer = setTimeout(onClose, 3000);
    return () => clearTimeout(timer);
  }, [onClose]);

  const style = TOAST_STYLES[type];

  return (
    <div
      className="fixed bottom-6 right-6 z-[100] px-4 py-3 rounded-lg shadow-soft-lg text-sm font-medium animate-[fadeIn_0.3s_ease,slideInRight_0.3s_ease]"
      style={{
        backgroundColor: style.background,
        color: style.color,
        borderColor: style.border,
      }}
    >
      {message}
    </div>
  );
}
