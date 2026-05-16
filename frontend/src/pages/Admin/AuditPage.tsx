import { useState, useEffect, useCallback } from 'react';
import { getAuditLogs } from '../../api/admin';
import StatusBadge from '../../components/admin/StatusBadge';
import { IconSearch, IconFilter } from '../../components/admin/Icons';
import type { AuditLog } from '../../types/admin';

export default function AuditPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [actionFilter, setActionFilter] = useState('all');
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const actions = [
    'all',
    'login',
    'logout',
    'user_created',
    'user_updated',
    'user_disabled',
    'user_enabled',
    'password_reset',
    'tenant_membership_added',
    'tenant_membership_removed',
    'role_assigned',
    'role_removed',
    'role_permissions_granted',
    'role_permission_revoked',
    'permission_created',
    'permission_updated',
    'permission_deleted',
    'oauth_client_changed',
    'admin_user_logout_all',
  ];

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getAuditLogs({
        action: actionFilter === 'all' ? undefined : actionFilter,
        page,
        page_size: 20,
      });
      setLogs(res.data);
      setTotal(res.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : '审计日志接口暂不可用');
    } finally {
      setLoading(false);
    }
  }, [actionFilter, page]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  const getActionLabel = (action: string) => {
    const labels: Record<string, string> = {
      'user.login': '用户登录',
      login: '用户登录',
      logout: '用户退出',
      user_created: '用户创建',
      user_updated: '用户更新',
      user_disabled: '用户禁用',
      user_enabled: '用户启用',
      password_reset: '密码重置',
      tenant_membership_added: '成员添加',
      tenant_membership_removed: '成员移除',
      role_assigned: '角色分配',
      role_removed: '角色移除',
      role_permissions_granted: '权限授予',
      role_permission_revoked: '权限撤销',
      permission_created: '权限创建',
      permission_updated: '权限更新',
      permission_deleted: '权限删除',
      oauth_client_changed: 'Client 变更',
      admin_user_logout_all: '强制下线',
    };
    return labels[action] || action;
  };

  return (
    <div className="animate-[fadeInUp_0.4s_ease]">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-ink mb-1">审计日志</h1>
        <p className="text-sm text-ink-tertiary">追踪所有身份相关操作，满足合规与溯源需求</p>
      </div>

      {error && (
        <div className="mb-5 rounded-xl bg-warn-soft px-4 py-3 text-sm text-warn">
          {error}。当前不会展示 mock 审计记录。
        </div>
      )}

      <div className="flex items-center gap-3 mb-5">
        <div className="flex-1 relative max-w-md">
          <IconSearch size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-tertiary" />
          <input
            type="text"
            placeholder="搜索操作者或目标..."
            className="w-full pl-10 pr-4 py-2 text-sm bg-surface-solid border border-line rounded-lg focus:outline-none focus:border-brand transition-all text-ink placeholder:text-ink-muted"
          />
        </div>
        <select
          value={actionFilter}
          onChange={e => { setActionFilter(e.target.value); setPage(1); }}
          className="px-3 py-2 text-sm bg-surface-solid border border-line rounded-lg focus:outline-none focus:border-brand text-ink-secondary"
        >
          {actions.map(a => (
            <option key={a} value={a}>{a === 'all' ? '全部操作' : getActionLabel(a)}</option>
          ))}
        </select>
        <button className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-ink-secondary bg-surface-solid border border-line rounded-lg hover:bg-surface-hover transition-colors">
          <IconFilter size={14} /> 时间范围
        </button>
      </div>

      <div className="bg-surface-solid rounded-[20px] border border-line overflow-hidden">
        {loading ? (
          <div className="p-6 space-y-4">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="flex items-center gap-4 animate-pulse">
                <div className="h-8 w-32 bg-surface-hover rounded" />
                <div className="flex-1 h-8 bg-surface-hover rounded" />
                <div className="h-8 w-24 bg-surface-hover rounded" />
              </div>
            ))}
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-line">
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-ink-tertiary uppercase tracking-wider">操作</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-ink-tertiary uppercase tracking-wider">操作者</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-ink-tertiary uppercase tracking-wider">目标</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-ink-tertiary uppercase tracking-wider">IP</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-ink-tertiary uppercase tracking-wider">时间</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-ink-tertiary uppercase tracking-wider">结果</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {logs.map((log) => (
                    <tr key={log.id} className="hover:bg-surface-hover transition-colors">
                      <td className="px-6 py-4">
                        <code className="text-xs font-mono bg-surface-hover px-2 py-0.5 rounded text-ink-secondary">{log.action}</code>
                      </td>
                      <td className="px-6 py-4 text-sm text-ink-secondary">{log.actor}</td>
                      <td className="px-6 py-4 text-sm font-mono text-ink-secondary">{log.target}</td>
                      <td className="px-6 py-4 text-sm font-mono text-ink-tertiary">{log.ip}</td>
                      <td className="px-6 py-4 text-sm text-ink-secondary">{log.time}</td>
                      <td className="px-6 py-4"><StatusBadge status={log.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="px-6 py-3 border-t border-line flex items-center justify-between">
              <span className="text-xs text-ink-tertiary">显示 {logs.length} 条，共 {total} 条</span>
              <div className="flex items-center gap-1">
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} className="px-3 py-1.5 text-xs text-ink-secondary bg-surface-hover rounded-md disabled:opacity-50">上一页</button>
                <span className="px-3 py-1.5 text-xs font-medium bg-ink text-ink-inverse rounded-md">{page}</span>
                <button onClick={() => setPage(p => p + 1)} disabled={logs.length < 20} className="px-3 py-1.5 text-xs text-ink-secondary hover:bg-surface-hover rounded-md disabled:opacity-50">下一页</button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
