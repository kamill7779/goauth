import { useCallback, useEffect, useState } from 'react';
import { getSessions, revokeSession } from '../../api/admin';
import StatusBadge from '../../components/admin/StatusBadge';
import Toast from '../../components/admin/Toast';
import { IconLogOut, IconRefreshCw, IconSearch } from '../../components/admin/Icons';
import type { Session } from '../../types/admin';

const PAGE_SIZE = 20;

function formatDate(value: string) {
  if (!value) {
    return '-';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString('zh-CN', { hour12: false });
}

export default function SessionsPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [total, setTotal] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [userId, setUserId] = useState('');
  const [statusFilter, setStatusFilter] = useState('active');
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [revokingSessionId, setRevokingSessionId] = useState<string | null>(null);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  const loadSessions = useCallback(async () => {
    const trimmedUserId = userId.trim();
    const parsedUserId = trimmedUserId ? Number(trimmedUserId) : undefined;
    if (parsedUserId !== undefined && (!Number.isInteger(parsedUserId) || parsedUserId <= 0)) {
      setToast({ message: '请输入有效的用户 ID', type: 'error' });
      setLoading(false);
      return;
    }

    setLoading(true);
    try {
      const data = await getSessions({
        search: searchQuery.trim() || undefined,
        status: statusFilter === 'all' ? undefined : statusFilter,
        user_id: parsedUserId,
        page,
        page_size: PAGE_SIZE,
      });
      setSessions(data.data);
      setTotal(data.total);
    } catch (err) {
      setToast({ message: err instanceof Error ? err.message : '加载失败', type: 'error' });
    } finally {
      setLoading(false);
    }
  }, [page, searchQuery, statusFilter, userId]);

  useEffect(() => {
    loadSessions();
  }, [loadSessions]);

  const handleRevoke = async (session: Session) => {
    if (session.status !== 'active') {
      return;
    }
    const confirmed = window.confirm(`确认强制下线 ${session.user} 的该会话？`);
    if (!confirmed) {
      return;
    }

    setRevokingSessionId(session.id);
    try {
      await revokeSession(session.id);
      setToast({ message: '该会话已强制下线，审计记录已保存', type: 'success' });
      await loadSessions();
    } catch (err) {
      setToast({ message: err instanceof Error ? err.message : '操作失败', type: 'error' });
    } finally {
      setRevokingSessionId(null);
    }
  };

  const filters = [
    { id: 'active', label: '活跃' },
    { id: 'all', label: '全部' },
    { id: 'revoked', label: '已下线' },
    { id: 'expired', label: '已过期' },
  ];

  return (
    <div className="animate-[fadeInUp_0.4s_ease]">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900 mb-1">会话管理</h1>
          <p className="text-sm text-gray-400">默认展示全局活跃会话，可按用户、邮箱、客户端和状态筛选并精确下线单个会话</p>
        </div>
        <button
          onClick={loadSessions}
          disabled={loading}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50"
        >
          <IconRefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          刷新
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-3 mb-5">
        <div className="flex-1 relative min-w-[260px] max-w-md">
          <IconSearch size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => { setSearchQuery(e.target.value); setPage(1); }}
            placeholder="搜索邮箱、用户名称、客户端或会话 ID..."
            className="w-full pl-10 pr-4 py-2 text-sm bg-white border border-gray-200 rounded-lg focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/20 transition-all placeholder:text-gray-300"
          />
        </div>
        <input
          type="number"
          min="1"
          value={userId}
          onChange={e => { setUserId(e.target.value); setPage(1); }}
          placeholder="用户 ID"
          className="w-32 rounded-lg border border-gray-200 bg-white px-3 py-2 text-sm text-gray-700 focus:border-blue-500 focus:outline-none"
        />
        <div className="flex items-center gap-1 bg-white border border-gray-200 rounded-lg p-0.5">
          {filters.map(filter => (
            <button
              key={filter.id}
              onClick={() => { setStatusFilter(filter.id); setPage(1); }}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                statusFilter === filter.id ? 'bg-gray-900 text-white' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'
              }`}
            >
              {filter.label}
            </button>
          ))}
        </div>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        {loading ? (
          <div className="p-6 space-y-4">
            {Array.from({ length: 5 }).map((_, index) => (
              <div key={index} className="h-12 rounded-lg bg-gray-100 animate-pulse" />
            ))}
          </div>
        ) : sessions.length === 0 ? (
          <div className="px-6 py-14 text-center">
            <div className="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-gray-100">
              <IconSearch size={18} className="text-gray-400" />
            </div>
            <p className="text-sm font-medium text-gray-700">暂无匹配会话</p>
            <p className="mt-1 text-xs text-gray-400">可切换到“全部”或清空筛选条件后重新查看。</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-200">
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">会话 ID</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">用户</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">客户端</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">IP 地址</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">状态</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">创建时间</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">过期时间</th>
                    <th className="w-10 px-6 py-3.5"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {sessions.map((session) => (
                    <tr key={session.id} className="hover:bg-gray-50 transition-colors">
                      <td className="px-6 py-4">
                        <div className="flex flex-col gap-1">
                          <code className="w-fit text-xs font-mono bg-gray-100 px-2 py-1 rounded text-gray-600">{session.id.slice(0, 18)}...</code>
                          <span className="text-[11px] text-gray-300">tenant:{session.tenant_id || '-'}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <p className="text-sm font-medium text-gray-800">{session.user || '-'}</p>
                        <p className="text-xs text-gray-400">user_id:{session.user_id || '-'}</p>
                      </td>
                      <td className="px-6 py-4">
                        <p className="max-w-[220px] truncate text-sm text-gray-600" title={session.client}>{session.client || '-'}</p>
                        {session.user_agent && <p className="max-w-[220px] truncate text-xs text-gray-300" title={session.user_agent}>{session.user_agent}</p>}
                      </td>
                      <td className="px-6 py-4 text-sm font-mono text-gray-500">{session.ip || '-'}</td>
                      <td className="px-6 py-4"><StatusBadge status={session.status} /></td>
                      <td className="px-6 py-4 text-sm text-gray-500">{formatDate(session.created_at)}</td>
                      <td className="px-6 py-4 text-sm text-gray-500">{formatDate(session.expires_at)}</td>
                      <td className="px-6 py-4">
                        <button
                          onClick={() => handleRevoke(session)}
                          disabled={session.status !== 'active' || revokingSessionId === session.id}
                          className="p-1.5 hover:bg-red-50 rounded-md transition-colors group disabled:cursor-not-allowed disabled:opacity-30"
                          title={session.status === 'active' ? '强制下线该会话' : '非活跃会话无需下线'}
                        >
                          <IconLogOut size={16} className="text-gray-400 group-hover:text-red-500" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="px-6 py-3 border-t border-gray-200 flex items-center justify-between">
              <span className="text-xs text-gray-400">显示 {sessions.length} 条，共 {total} 条</span>
              <div className="flex items-center gap-1">
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} className="px-3 py-1.5 text-xs text-gray-500 bg-gray-100 rounded-md disabled:opacity-50">上一页</button>
                <span className="px-3 py-1.5 text-xs font-medium bg-gray-900 text-white rounded-md">{page}</span>
                <button onClick={() => setPage(p => p + 1)} disabled={page * PAGE_SIZE >= total} className="px-3 py-1.5 text-xs text-gray-500 hover:bg-gray-100 rounded-md disabled:opacity-50">下一页</button>
              </div>
            </div>
          </>
        )}
      </div>

      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
}
