import { useState } from 'react';
import { getUserSessions, revokeUserSessions } from '../../api/admin';
import Toast from '../../components/admin/Toast';
import { IconLogOut } from '../../components/admin/Icons';
import type { Session } from '../../types/admin';

export default function SessionsPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [userId, setUserId] = useState('');
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  const loadSessions = async () => {
    const parsedUserId = Number(userId);
    if (!Number.isInteger(parsedUserId) || parsedUserId <= 0) {
      setToast({ message: '请输入有效的用户 ID', type: 'error' });
      return;
    }
    setLoading(true);
    try {
      const data = await getUserSessions(parsedUserId);
      setSessions(data);
    } catch (err) {
      setToast({ message: err instanceof Error ? err.message : '加载失败', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const handleRevoke = async (_sessionId: string, targetUserId: number) => {
    try {
      await revokeUserSessions(targetUserId);
      setToast({ message: `用户 ${targetUserId} 的会话已强制下线，审计记录已保存`, type: 'success' });
      setSessions([]);
    } catch (err) {
      setToast({ message: err instanceof Error ? err.message : '操作失败', type: 'error' });
    }
  };

  return (
    <div className="animate-[fadeInUp_0.4s_ease]">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-gray-900 mb-1">会话管理</h1>
        <p className="text-sm text-gray-400">查看活跃会话、管理 Refresh Token、执行强制下线</p>
      </div>

      <div className="mb-4">
        <input
          type="number"
          min="1"
          value={userId}
          onChange={e => setUserId(e.target.value)}
          placeholder="输入用户 ID"
          className="mr-3 w-40 rounded-lg border border-gray-200 bg-white px-3 py-2 text-sm text-gray-700 focus:border-blue-500 focus:outline-none"
        />
        <button
          onClick={loadSessions}
          disabled={loading}
          className="px-4 py-2 text-sm bg-gray-900 text-white rounded-lg hover:bg-gray-800 transition-colors disabled:opacity-50"
        >
          {loading ? '加载中...' : '加载会话'}
        </button>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">会话 ID</th>
                <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">用户</th>
                <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">客户端</th>
                <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">IP 地址</th>
                <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">创建时间</th>
                <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">过期时间</th>
                <th className="w-10 px-6 py-3.5"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {sessions.map((session) => (
                <tr key={session.id} className="hover:bg-gray-50 transition-colors">
                  <td className="px-6 py-4">
                    <code className="text-xs font-mono bg-gray-100 px-2 py-1 rounded text-gray-600">{session.id}</code>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-700">{session.user}</td>
                  <td className="px-6 py-4 text-sm text-gray-500">{session.client}</td>
                  <td className="px-6 py-4 text-sm font-mono text-gray-500">{session.ip}</td>
                  <td className="px-6 py-4 text-sm text-gray-500">{session.created_at}</td>
                  <td className="px-6 py-4 text-sm text-gray-500">{session.expires_at}</td>
                  <td className="px-6 py-4">
                    <button
                      onClick={() => handleRevoke(session.id, 1)}
                      className="p-1.5 hover:bg-red-50 rounded-md transition-colors group"
                      title="强制下线"
                    >
                      <IconLogOut size={16} className="text-gray-400 group-hover:text-red-500" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
}
