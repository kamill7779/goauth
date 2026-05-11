import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getDashboard } from '../../api/admin';
import { IconUsers, IconMonitor, IconBuilding, IconKey, IconAlertTriangle } from '../../components/admin/Icons';
import StatusBadge from '../../components/admin/StatusBadge';
import type { DashboardStats, RecentLogin, PermissionChange, Alert } from '../../types/admin';

function SkeletonCard() {
  return (
    <div className="bg-surface-solid rounded-xl border border-line p-5 animate-pulse">
      <div className="h-4 w-24 bg-surface-hover rounded mb-4" />
      <div className="h-8 w-16 bg-surface-hover rounded mb-2" />
      <div className="h-3 w-20 bg-surface-hover rounded" />
    </div>
  );
}

export default function DashboardPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [logins, setLogins] = useState<RecentLogin[]>([]);
  const [changes, setChanges] = useState<PermissionChange[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    getDashboard()
      .then(d => {
        setStats(d.stats);
        setLogins(d.recent_logins);
        setChanges(d.permission_changes);
        setAlerts(d.alerts);
      })
      .catch(err => setError(err instanceof Error ? err.message : '总览接口暂不可用'))
      .finally(() => setLoading(false));
  }, []);

  const statItems = [
    { label: '总用户数', value: stats?.total_users ?? 0, change: stats?.users_change, icon: IconUsers, path: '/admin/users' },
    { label: '活跃会话', value: stats?.active_sessions ?? 0, change: stats?.sessions_change, icon: IconMonitor, path: '/admin/sessions' },
    { label: '租户数', value: stats?.total_tenants ?? 0, change: stats?.tenants_change, icon: IconBuilding, path: '/admin/tenants' },
    { label: 'OAuth Clients', value: stats?.total_oauth_clients ?? 0, change: stats?.clients_change, icon: IconKey, path: '/admin/oauth' },
  ];

  return (
    <div className="animate-[fadeInUp_0.4s_ease]">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-ink mb-1">总览</h1>
        <p className="text-sm text-ink-tertiary">GoAuth 身份基础设施实时状态</p>
      </div>

      {error && (
        <div className="mb-5 rounded-xl bg-warn-soft px-4 py-3 text-sm text-warn">
          {error}。当前页面只展示已接入接口返回的数据，不再使用 mock 数据兜底。
        </div>
      )}

      <div className="grid grid-cols-4 gap-5 mb-8">
        {loading
          ? Array.from({ length: 4 }).map((_, i) => <SkeletonCard key={i} />)
          : statItems.map((stat, i) => {
              const Icon = stat.icon;
              const isPositive = (stat.change ?? '').startsWith('+');
              return (
                <div
                  key={i}
                  onClick={() => navigate(stat.path)}
                  className="bg-surface-solid rounded-xl border border-line p-5 hover:shadow-soft-md hover:-translate-y-0.5 cursor-pointer transition-all duration-300"
                  style={{ animationDelay: `${i * 0.08}s` }}
                >
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-xs font-medium text-ink-tertiary">{stat.label}</span>
                    <div className="w-8 h-8 rounded-lg bg-surface-hover flex items-center justify-center">
                      <Icon size={16} className="text-ink-secondary" />
                    </div>
                  </div>
                  <div className="text-2xl font-semibold text-ink mb-1">{stat.value.toLocaleString()}</div>
                  <div className={`text-xs font-medium flex items-center gap-1 ${isPositive ? 'text-ok' : 'text-danger'}`}>
                    {stat.change}
                    <span className="text-ink-tertiary font-normal">较上周</span>
                  </div>
                </div>
              );
            })}
      </div>

      <div className="grid grid-cols-3 gap-5">
        <div className="col-span-2 bg-surface-solid rounded-xl border border-line overflow-hidden">
          <div className="px-5 py-4 border-b border-line flex items-center justify-between">
            <h2 className="text-sm font-semibold text-ink">最近登录</h2>
            <button onClick={() => navigate('/admin/audit')} className="text-xs text-brand hover:underline flex items-center gap-1">
              查看全部 →
            </button>
          </div>
          <div className="divide-y divide-line">
            {logins.map((login) => (
              <div key={login.id} className="px-5 py-3.5 flex items-center gap-4 hover:bg-surface-hover transition-colors">
                <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                  login.status === 'success' ? 'bg-ok' :
                  login.status === 'failed' ? 'bg-warn' : 'bg-danger'
                }`} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-ink truncate">{login.user}</p>
                  <p className="text-xs text-ink-tertiary">{login.ip} · {login.location}</p>
                </div>
                <StatusBadge status={login.status} />
                <span className="text-xs text-ink-tertiary w-20 text-right">{login.time}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="space-y-5">
          <div className="bg-surface-solid rounded-xl border border-line overflow-hidden">
            <div className="px-5 py-4 border-b border-line">
              <h2 className="text-sm font-semibold text-ink">权限变更</h2>
            </div>
            <div className="divide-y divide-line">
              {changes.map((item, i) => (
                <div key={i} className="px-5 py-3.5">
                  <p className="text-sm text-ink-secondary">{item.action}</p>
                  <div className="flex items-center justify-between mt-1">
                    <span className="text-xs text-ink-tertiary">{item.user}</span>
                    <span className="text-xs text-ink-muted">{item.time}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-surface-solid rounded-xl border border-line overflow-hidden">
            <div className="px-5 py-4 border-b border-line flex items-center justify-between">
              <h2 className="text-sm font-semibold text-ink">异常登录</h2>
              <span className="px-2 py-0.5 text-[10px] font-medium bg-danger-soft text-danger rounded-full">{alerts.length} 条</span>
            </div>
            <div className="divide-y divide-line">
              {alerts.map((alert, i) => (
                <div key={i} className="px-5 py-3.5 flex items-start gap-3">
                  <IconAlertTriangle size={16} className="text-warn mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="text-sm text-ink-secondary">{alert.user}</p>
                    <p className="text-xs text-ink-tertiary mt-0.5">{alert.ip} · {alert.time}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
