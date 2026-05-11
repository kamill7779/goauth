import { useEffect, useRef, useState } from 'react';
import { useTheme, type ThemePreference } from '../../hooks/useTheme';

function IconSun({ size = 16, className = '' }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2" />
      <path d="M12 20v2" />
      <path d="m4.93 4.93 1.41 1.41" />
      <path d="m17.66 17.66 1.41 1.41" />
      <path d="M2 12h2" />
      <path d="M20 12h2" />
      <path d="m4.93 19.07 1.41-1.41" />
      <path d="m17.66 6.34 1.41-1.41" />
    </svg>
  );
}

function IconMoon({ size = 16, className = '' }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  );
}

function IconLaptop({ size = 16, className = '' }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <rect width="18" height="12" x="3" y="4" rx="2" />
      <path d="M2 20h20" />
    </svg>
  );
}

function IconCheck({ size = 14, className = '' }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

interface ThemeToggleProps {
  /** Visual variant. `chip` matches header chrome; `inline` is a transparent square. */
  variant?: 'chip' | 'inline';
  /** Optional aria-label override. */
  label?: string;
  /** Where the menu opens relative to the trigger. Defaults to right-aligned. */
  align?: 'left' | 'right';
}

const OPTIONS: Array<{ id: ThemePreference; label: string; description: string; icon: typeof IconSun }> = [
  { id: 'light', label: '浅色', description: '始终使用浅色界面', icon: IconSun },
  { id: 'dark', label: '深色', description: '始终使用深色界面', icon: IconMoon },
  { id: 'system', label: '跟随系统', description: '随操作系统主题切换', icon: IconLaptop },
];

export default function ThemeToggle({ variant = 'chip', label = '切换主题', align = 'right' }: ThemeToggleProps) {
  const { preference, resolved, setPreference } = useTheme();
  const [open, setOpen] = useState(false);
  const wrapperRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) {
      return;
    }
    const handleClickOutside = (event: MouseEvent) => {
      if (wrapperRef.current && !wrapperRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleEscape);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleEscape);
    };
  }, [open]);

  const TriggerIcon = preference === 'system' ? IconLaptop : resolved === 'dark' ? IconMoon : IconSun;
  const triggerClasses = variant === 'chip'
    ? 'p-2 rounded-lg hover:bg-surface-hover transition-colors text-ink-secondary'
    : 'inline-flex h-9 w-9 items-center justify-center rounded-lg border border-line bg-surface-solid text-ink-secondary hover:bg-surface-hover transition-colors';

  return (
    <div className="relative" ref={wrapperRef}>
      <button
        type="button"
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen(value => !value)}
        className={triggerClasses}
      >
        <TriggerIcon size={variant === 'chip' ? 18 : 16} />
      </button>

      {open && (
        <div
          role="menu"
          aria-label={label}
          className={`absolute top-full mt-2 w-56 bg-surface-solid rounded-xl border border-line shadow-soft-lg overflow-hidden z-[60] ${align === 'left' ? 'left-0' : 'right-0'}`}
        >
          <div className="px-4 py-2.5 border-b border-line">
            <p className="text-xs font-medium text-ink-tertiary uppercase tracking-wider">主题</p>
          </div>
          <div className="py-1">
            {OPTIONS.map(option => {
              const Icon = option.icon;
              const active = preference === option.id;
              return (
                <button
                  key={option.id}
                  type="button"
                  role="menuitemradio"
                  aria-checked={active}
                  onClick={() => {
                    setPreference(option.id);
                    setOpen(false);
                  }}
                  className={`w-full flex items-center gap-3 px-4 py-2.5 text-left text-sm transition-colors ${
                    active ? 'text-ink' : 'text-ink-secondary hover:text-ink hover:bg-surface-hover'
                  }`}
                >
                  <span className={`flex h-7 w-7 items-center justify-center rounded-md ${active ? 'bg-brand-soft text-brand' : 'bg-surface-hover text-ink-tertiary'}`}>
                    <Icon size={14} />
                  </span>
                  <span className="flex-1">
                    <span className="block text-sm font-medium">{option.label}</span>
                    <span className="block text-[11px] text-ink-tertiary mt-0.5">{option.description}</span>
                  </span>
                  {active && <IconCheck size={14} className="text-brand" />}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
