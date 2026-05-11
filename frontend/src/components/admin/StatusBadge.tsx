type BadgeStyle = {
  background: string;
  color: string;
  border: string;
  dot: string;
};

const STYLE_MAP: Record<string, BadgeStyle> = {
  active: { background: 'var(--success-soft)', color: 'var(--success)', border: 'transparent', dot: 'var(--success)' },
  success: { background: 'var(--success-soft)', color: 'var(--success)', border: 'transparent', dot: 'var(--success)' },
  pending: { background: 'var(--warning-soft)', color: 'var(--warning)', border: 'transparent', dot: 'var(--warning)' },
  trial: { background: 'var(--warning-soft)', color: 'var(--warning)', border: 'transparent', dot: 'var(--warning)' },
  expired: { background: 'var(--warning-soft)', color: 'var(--warning)', border: 'transparent', dot: 'var(--warning)' },
  disabled: { background: 'var(--surface-hover)', color: 'var(--ink-secondary)', border: 'transparent', dot: 'var(--ink-tertiary)' },
  inactive: { background: 'var(--surface-hover)', color: 'var(--ink-secondary)', border: 'transparent', dot: 'var(--ink-tertiary)' },
  revoked: { background: 'var(--surface-hover)', color: 'var(--ink-secondary)', border: 'transparent', dot: 'var(--ink-tertiary)' },
  suspended: { background: 'var(--error-soft)', color: 'var(--error)', border: 'transparent', dot: 'var(--error)' },
  blocked: { background: 'var(--error-soft)', color: 'var(--error)', border: 'transparent', dot: 'var(--error)' },
  failed: { background: 'var(--error-soft)', color: 'var(--error)', border: 'transparent', dot: 'var(--error)' },
};

const LABEL_MAP: Record<string, string> = {
  active: '活跃',
  disabled: '停用',
  inactive: '停用',
  revoked: '已下线',
  pending: '待验证',
  suspended: '已冻结',
  blocked: '已拦截',
  failed: '失败',
  success: '成功',
  trial: '试用',
  expired: '已过期',
};

const FALLBACK: BadgeStyle = STYLE_MAP.inactive;

export default function StatusBadge({ status, text }: { status: string; text?: string }) {
  const style = STYLE_MAP[status] || FALLBACK;
  const label = text || LABEL_MAP[status] || status;

  return (
    <span
      className="inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full border"
      style={{ backgroundColor: style.background, color: style.color, borderColor: style.border }}
    >
      <span className="w-1.5 h-1.5 rounded-full mr-1.5" style={{ backgroundColor: style.dot }} />
      {label}
    </span>
  );
}
