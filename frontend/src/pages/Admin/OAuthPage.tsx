import { useState, useEffect } from 'react';
import { getOAuthClients } from '../../api/admin';
import StatusBadge from '../../components/admin/StatusBadge';
import { IconPlus, IconRefreshCw } from '../../components/admin/Icons';
import type { OAuthClient } from '../../types/admin';

export default function OAuthPage() {
  const [clients, setClients] = useState<OAuthClient[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    getOAuthClients()
      .then(setClients)
      .catch(err => setError(err instanceof Error ? err.message : 'OAuth Client 接口暂不可用'))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="animate-[fadeInUp_0.4s_ease]">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900 mb-1">OAuth Clients</h1>
          <p className="text-sm text-gray-400">管理 OIDC/OAuth 2.0 客户端、密钥和授权范围</p>
        </div>
        <button className="inline-flex items-center gap-2 px-4 py-2 bg-gray-900 text-white text-sm font-medium rounded-lg hover:bg-gray-800 transition-colors">
          <IconPlus size={16} /> 注册 Client
        </button>
      </div>

      {error && (
        <div className="mb-5 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-700">
          {error}
        </div>
      )}

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        {loading ? (
          <div className="p-6 space-y-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="flex items-center gap-4 animate-pulse">
                <div className="h-12 w-48 bg-gray-200 rounded" />
                <div className="flex-1 h-8 bg-gray-200 rounded" />
                <div className="h-8 w-24 bg-gray-200 rounded" />
              </div>
            ))}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200">
                  <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">应用名称</th>
                  <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">Client ID</th>
                  <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">Scopes</th>
                  <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">状态</th>
                  <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">自动成员</th>
                  <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">密钥轮换</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {clients.map((client) => (
                  <tr key={client.client_id} className="hover:bg-gray-50 transition-colors">
                    <td className="px-6 py-4">
                      <p className="text-sm font-medium text-gray-800">{client.name}</p>
                      <p className="text-xs text-gray-400 mt-0.5">{client.redirect_uris.length} 个回调地址</p>
                    </td>
                    <td className="px-6 py-4">
                      <code className="text-xs font-mono bg-gray-100 px-2 py-1 rounded text-gray-600">{client.client_id}</code>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-wrap gap-1">
                        {client.scopes.map(s => (
                          <span key={s} className="px-1.5 py-0.5 text-[10px] font-medium bg-gray-100 text-gray-600 rounded">{s}</span>
                        ))}
                      </div>
                    </td>
                    <td className="px-6 py-4"><StatusBadge status={client.status} /></td>
                    <td className="px-6 py-4">
                      {client.auto_provision_members ? (
                        <span className="inline-flex items-center gap-1 text-xs text-emerald-600">
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg> 已启用
                        </span>
                      ) : (
                        <span className="text-xs text-gray-400">-</span>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-gray-500">{client.last_rotated}</span>
                        <button className="p-1 hover:bg-gray-200 rounded transition-colors" title="轮换密钥">
                          <IconRefreshCw size={14} className="text-gray-400" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
