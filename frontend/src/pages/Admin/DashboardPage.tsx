import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getDashboard } from '../../api/admin';
import { IconUsers, IconMonitor, IconBuilding, IconKey, IconAlertTriangle } from '../../components/admin/Icons';
import StatusBadge from '../../components/admin/StatusBadge';
import type { DashboardStats, RecentLogin, PermissionChange, Alert } from '../../types/admin';

function SkeletonCard() {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5 animate-pulse">
      <div className="h-4 w-24 bg-gray-200 rounded mb-4" />
      <div className="h-8 w-16 bg-gray-200 rounded mb-2" />
      <div className="h-3 w-20 bg-gray-200 rounded" />
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
        <h1 className="text-2xl font-semibold text-gray-900 mb-1">总览</h1>
        <p className="text-sm text-gray-400">GoAuth 身份基础设施实时状态</p>
      </div>

      {error && (
        <div className="mb-5 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-700">
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
                  className="bg-white rounded-xl border border-gray-200 p-5 hover:shadow-md hover:-translate-y-0.5 cursor-pointer transition-all duration-300"
                  style={{ animationDelay: `${i * 0.08}s` }}
                >
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-xs font-medium text-gray-400">{stat.label}</span>
                    <div className="w-8 h-8 rounded-lg bg-gray-100 flex items-center justify-center">
                      <Icon size={16} className="text-gray-500" />
                    </div>
                  </div>
                  <div className="text-2xl font-semibold text-gray-900 mb-1">{stat.value.toLocaleString()}</div>
                  <div className={`text-xs font-medium flex items-center gap-1 ${isPositive ? 'text-emerald-600' : 'text-red-600'}`}>
                    {stat.change}
                    <span className="text-gray-400 font-normal">较上周</span>
                  </div>
                </div>
              );
            })}
      </div>

      <div className="grid grid-cols-3 gap-5">
        <div className="col-span-2 bg-white rounded-xl border border-gray-200 overflow-hidden">
          <div className="px-5 py-4 border-b border-gray-200 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-gray-800">最近登录</h2>
            <button onClick={() => navigate('/admin/audit')} className="text-xs text-blue-600 hover:underline flex items-center gap-1">
              查看全部 →
            </button>
          </div>
          <div className="divide-y divide-gray-100">
            {logins.map((login) => (
              <div key={login.id} className="px-5 py-3.5 flex items-center gap-4 hover:bg-gray-50 transition-colors">
                <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                  login.status === 'success' ? 'bg-emerald-500' :
                  login.status === 'failed' ? 'bg-amber-500' : 'bg-red-500'
                }`} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-800 truncate">{login.user}</p>
                  <p className="text-xs text-gray-400">{login.ip} · {login.location}</p>
                </div>
                <StatusBadge status={login.status} />
                <span className="text-xs text-gray-400 w-20 text-right">{login.time}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="space-y-5">
          <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
            <div className="px-5 py-4 border-b border-gray-200">
              <h2 className="text-sm font-semibold text-gray-800">权限变更</h2>
            </div>
            <div className="divide-y divide-gray-100">
              {changes.map((item, i) => (
                <div key={i} className="px-5 py-3.5">
                  <p className="text-sm text-gray-700">{item.action}</p>
                  <div className="flex items-center justify-between mt-1">
                    <span className="text-xs text-gray-400">{item.user}</span>
                    <span className="text-xs text-gray-300">{item.time}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
            <div className="px-5 py-4 border-b border-gray-200 flex items-center justify-between">
              <h2 className="text-sm font-semibold text-gray-800">异常登录</h2>
              <span className="px-2 py-0.5 text-[10px] font-medium bg-red-50 text-red-600 rounded-full">{alerts.length} 条</span>
            </div>
            <div className="divide-y divide-gray-100">
              {alerts.map((alert, i) => (
                <div key={i} className="px-5 py-3.5 flex items-start gap-3">
                  <IconAlertTriangle size={16} className="text-amber-500 mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="text-sm text-gray-700">{alert.user}</p>
                    <p className="text-xs text-gray-400 mt-0.5">{alert.ip} · {alert.time}</p>
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
