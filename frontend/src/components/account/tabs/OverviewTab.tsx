import {
  IconKey,
  IconShield,
  IconApps,
  IconSparkle,
  IconEdit,
  IconCheck,
  IconInfo,
  IconArrowRight,
  IconMonitor,
  IconRefreshCw,
} from '../../admin/Icons';
import type { SharedTabProps } from './types';

export default function OverviewTab({
  user,
  loginMethods,
  authorizedApps,
  twoFAEnabled,
  securityScore,
  sessions,
  identityActivities,
  setTab,
  refresh,
}: SharedTabProps) {
  const boundCount = loginMethods.filter((m) => m.bound).length;

  const summaryCards = [
    {
      label: '登录方式',
      value: boundCount,
      unit: '种',
      hint: boundCount >= 2 ? '已建立多重入口' : '建议至少 2 种',
      tone: boundCount >= 2 ? ('ok' as const) : ('warn' as const),
      icon: IconKey,
    },
    {
      label: '两步验证',
      value: twoFAEnabled ? '已开启' : '未开启',
      hint: twoFAEnabled ? '你的账号有第二把锁' : '建议立即开启',
      tone: twoFAEnabled ? ('ok' as const) : ('warn' as const),
      icon: IconShield,
      isText: true,
    },
    {
      label: '已授权应用',
      value: authorizedApps.length,
      unit: '个',
      hint: '在统一身份下登录',
      tone: 'neutral' as const,
      icon: IconApps,
    },
    {
      label: '安全等级',
      value: securityScore,
      unit: '/100',
      hint: securityScore >= 80 ? '已达推荐水准' : '再加一道锁更稳',
      tone: securityScore >= 80 ? ('ok' as const) : ('warn' as const),
      icon: IconSparkle,
      isScore: true,
    },
  ];

  const quickActions = [
    { label: '编辑资料', icon: IconEdit, target: 'profile' as const },
    { label: '管理登录方式', icon: IconKey, target: 'login' as const },
    { label: twoFAEnabled ? '查看两步验证' : '开启两步验证', icon: IconShield, target: 'security' as const, emphasize: !twoFAEnabled },
    { label: '查看已授权应用', icon: IconApps, target: 'apps' as const },
  ];

  const visibleAlerts = [
    ...(twoFAEnabled ? [] : [{ id: 'no-2fa', level: 'warning' as const, title: '尚未开启两步验证', desc: '两步验证能在密码泄露时为你的账号上一道锁。', action: '去开启' }]),
    ...(boundCount < 2 ? [{ id: 'single-method', level: 'warning' as const, title: '仅绑定单一登录方式', desc: '建议至少绑定 2 种登录方式，避免一个失效后无法登入。', action: '去绑定' }] : []),
    ...(!user.email_verified ? [{ id: 'email-unverified', level: 'danger' as const, title: '邮箱尚未验证', desc: '未验证邮箱无法用于重置密码与接收安全通知。', action: '立即验证' }] : []),
  ];

  const activeCount = sessions.filter((s) => s.status === 'active').length;
  const activityIconMap = {
    security: IconShield,
    auth: IconApps,
    binding: IconKey,
    profile: IconEdit,
  };

  return (
    <div className="space-y-5">
      {/* Summary cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {summaryCards.map((c, i) => {
          const TabIcon = c.icon;
          const toneColor =
            c.tone === 'ok'
              ? 'text-ok bg-ok-soft border-ok-soft'
              : c.tone === 'warn'
                ? 'text-warn bg-warn-soft border-warn-soft'
                : 'text-brand bg-brand-soft border-brand-soft';
          return (
            <div
              key={c.label}
              className="relative overflow-hidden rounded-[20px] border border-line bg-surface-solid p-5 shadow-soft-sm transition-all hover:-translate-y-0.5 hover:shadow-soft-md"
              style={{ animationDelay: `${i * 60}ms` }}
            >
              <div className="flex items-center justify-between">
                <div className={`inline-flex h-9 w-9 items-center justify-center rounded-xl ${toneColor}`}>
                  <TabIcon size={18} />
                </div>
                {c.tone === 'warn' && <span className="h-2 w-2 animate-pulse rounded-full bg-warn" />}
              </div>
              <div className="mt-4 flex items-baseline gap-1">
                {c.isText ? (
                  <span className="text-2xl font-semibold">{c.value}</span>
                ) : (
                  <>
                    <span className="text-3xl font-semibold tracking-tight">{c.value}</span>
                    <span className="text-sm text-ink-tertiary">{c.unit}</span>
                  </>
                )}
              </div>
              <div className="mt-1 text-sm text-ink-secondary">{c.label}</div>
              <div className="mt-3 h-px bg-line" />
              <div className={`mt-2 text-xs ${c.tone === 'warn' ? 'text-warn' : 'text-ink-tertiary'}`}>{c.hint}</div>
            </div>
          );
        })}
      </div>

      {/* Quick actions */}
      <div className="rounded-[20px] border border-line bg-surface-solid p-6 shadow-soft-sm">
        <div className="mb-4">
          <h2 className="text-lg font-semibold text-ink">快捷操作</h2>
          <p className="mt-1 text-sm text-ink-tertiary">一步直达常用入口</p>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {quickActions.map((a) => {
            const Icon = a.icon;
            return (
              <button
                key={a.label}
                onClick={() => setTab(a.target)}
                className={`flex items-center gap-3 rounded-2xl border p-4 text-left transition-all hover:-translate-y-0.5 hover:shadow-soft-md ${
                  a.emphasize
                    ? 'border-ink bg-ink text-ink-inverse'
                    : 'border-line bg-surface-muted text-ink hover:border-line-strong'
                }`}
              >
                <span className={`inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl ${a.emphasize ? 'bg-white/10 text-[#DDB07F]' : 'bg-surface-hover text-brand'}`}>
                  <Icon size={18} />
                </span>
                <span className="flex-1 text-sm font-medium">{a.label}</span>
                <IconArrowRight size={16} className="shrink-0 opacity-50" />
              </button>
            );
          })}
        </div>
      </div>

      {/* Sessions summary */}
      <div className="rounded-[20px] border border-line bg-surface-solid p-6 shadow-soft-sm">
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-ink">活跃会话</h2>
            <p className="mt-1 text-sm text-ink-tertiary">当前有 {activeCount} 个活跃会话</p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={refresh}
              className="inline-flex items-center gap-2 rounded-xl border border-line bg-surface-muted px-4 py-2 text-sm font-medium text-ink-secondary transition-colors hover:bg-surface-hover"
            >
              <IconRefreshCw size={14} />
              刷新
            </button>
            <button
              onClick={() => setTab('security')}
              className="inline-flex items-center gap-2 rounded-xl border border-line bg-surface-muted px-4 py-2 text-sm font-medium text-ink-secondary transition-colors hover:bg-surface-hover"
            >
              <IconMonitor size={14} />
              管理会话
            </button>
          </div>
        </div>
      </div>

      {/* Alerts + Timeline */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        {/* Security alerts */}
        <div className="rounded-[20px] border border-line bg-surface-solid p-6 shadow-soft-sm">
          <div className="mb-4">
            <h2 className="text-lg font-semibold text-ink">安全提醒</h2>
            <p className="mt-1 text-sm text-ink-tertiary">{visibleAlerts.length ? `${visibleAlerts.length} 条待处理` : '一切安好'}</p>
          </div>
          {visibleAlerts.length === 0 ? (
            <div className="flex flex-col items-center py-10 text-center">
              <div className="mb-4 inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-ok-soft text-ok">
                <IconCheck size={24} />
              </div>
              <p className="text-base font-medium">目前没有需要关注的提醒</p>
              <p className="mt-1 max-w-xs text-sm text-ink-tertiary">保持现状即可。我们会在身份相关变更发生时第一时间告诉你。</p>
            </div>
          ) : (
            <div className="space-y-3">
              {visibleAlerts.map((a) => (
                <div
                  key={a.id}
                  className={`flex items-start gap-3 rounded-2xl border p-4 ${
                    a.level === 'danger'
                      ? 'border-danger/20 bg-danger-soft'
                      : 'border-warn/20 bg-warn-soft'
                  }`}
                >
                  <span className={a.level === 'danger' ? 'text-danger' : 'text-warn'} style={{ marginTop: 2 }}>
                    <IconInfo size={16} />
                  </span>
                  <div className="flex-1">
                    <div className={`text-sm font-medium ${a.level === 'danger' ? 'text-danger' : 'text-warn'}`}>{a.title}</div>
                    <div className="mt-1 text-xs leading-relaxed text-ink-secondary">{a.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Timeline */}
        <div className="rounded-[20px] border border-line bg-surface-solid p-6 shadow-soft-sm">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-ink">最近身份活动</h2>
              <p className="mt-1 text-sm text-ink-tertiary">只展示与你身份有关的事件</p>
            </div>
          </div>
          {identityActivities.length === 0 ? (
            <div className="flex flex-col items-center py-10 text-center">
              <div className="mb-4 inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-surface-muted text-ink-tertiary">
                <IconInfo size={24} />
              </div>
              <p className="text-base font-medium">暂无身份活动</p>
              <p className="mt-1 max-w-xs text-sm text-ink-tertiary">登录、资料变更、绑定变更等事件会出现在这里。</p>
            </div>
          ) : (
            <div className="relative pl-6">
              <div className="absolute bottom-4 left-[11px] top-4 w-px bg-line" />
              {identityActivities.map((act) => {
                const ActivityIcon = activityIconMap[act.type] || IconInfo;
                return (
                  <div key={act.id} className="relative mb-5">
                    <span className="absolute -left-6 top-0.5 flex h-5 w-5 items-center justify-center rounded-full border-2 border-brand bg-surface-solid">
                      <span className="h-1.5 w-1.5 rounded-full bg-brand" />
                    </span>
                    <div className="flex items-start gap-2">
                      <ActivityIcon size={14} className="mt-0.5 shrink-0 text-brand" />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-baseline justify-between gap-3">
                          <span className="text-sm font-medium">{act.title}</span>
                          <span className="shrink-0 text-[11px] text-ink-tertiary">{act.time}</span>
                        </div>
                        {act.desc && <div className="mt-1 text-xs leading-relaxed text-ink-tertiary">{act.desc}</div>}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
