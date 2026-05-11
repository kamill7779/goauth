import { useState, useEffect, useCallback } from 'react';
import { getUsers, disableUser, enableUser, resetPassword } from '../../api/admin';
import StatusBadge from '../../components/admin/StatusBadge';
import Drawer from '../../components/admin/Drawer';
import Toast from '../../components/admin/Toast';
import { IconSearch, IconPlus, IconFilter, IconCheckCircle, IconClock, IconRefreshCw, IconLock } from '../../components/admin/Icons';
import type { User } from '../../types/admin';

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [total, setTotal] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sort, setSort] = useState('created_at_desc');
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [showConfirm, setShowConfirm] = useState<{ userId: number; action: string } | null>(null);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getUsers({
        search: searchQuery || undefined,
        status: statusFilter === 'all' ? undefined : statusFilter,
        sort,
        page,
        page_size: 20,
      });
      setUsers(res.data);
      setTotal(res.total);
    } catch (err) {
      setToast({ message: err instanceof Error ? err.message : '加载失败', type: 'error' });
    } finally {
      setLoading(false);
    }
  }, [searchQuery, statusFilter, sort, page]);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  const openUserDrawer = (user: User) => {
    setSelectedUser(user);
    setDrawerOpen(true);
  };

  const handleStatusChange = async (userId: number, action: string) => {
    try {
      if (action === 'disable') await disableUser(userId);
      else await enableUser(userId);
      setShowConfirm(null);
      setToast({
        message: `用户已${action === 'disable' ? '禁用' : '启用'}，审计记录已保存`,
        type: 'success',
      });
      fetchUsers();
    } catch (err) {
      setToast({ message: err instanceof Error ? err.message : '操作失败', type: 'error' });
    }
  };

  const handleResetPassword = async (userId: number) => {
    const newPassword = window.prompt('请输入临时新密码（至少 8 位），提交后会立即生效');
    if (!newPassword) {
      return;
    }
    if (newPassword.length < 8) {
      setToast({ message: '临时密码至少 8 位', type: 'error' });
      return;
    }
    try {
      await resetPassword(userId, newPassword);
      setToast({ message: '密码已重置，审计记录已保存', type: 'success' });
    } catch (err) {
      setToast({ message: err instanceof Error ? err.message : '操作失败', type: 'error' });
    }
  };

  const filters = [
    { id: 'all', label: '全部' },
    { id: 'active', label: '活跃' },
    { id: 'disabled', label: '停用' },
  ];

  return (
    <div className="animate-[fadeInUp_0.4s_ease]">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900 mb-1">用户管理</h1>
          <p className="text-sm text-gray-400">管理系统用户、租户成员和权限分配</p>
        </div>
        <button className="inline-flex items-center gap-2 px-4 py-2 bg-gray-900 text-white text-sm font-medium rounded-lg hover:bg-gray-800 transition-colors">
          <IconPlus size={16} /> 创建用户
        </button>
      </div>

      <div className="flex items-center gap-3 mb-5">
        <div className="flex-1 relative max-w-md">
          <IconSearch size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => { setSearchQuery(e.target.value); setPage(1); }}
            placeholder="搜索用户姓名或邮箱..."
            className="w-full pl-10 pr-4 py-2 text-sm bg-white border border-gray-200 rounded-lg focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/20 transition-all placeholder:text-gray-300"
          />
        </div>
        <div className="flex items-center gap-1 bg-white border border-gray-200 rounded-lg p-0.5">
          {filters.map(f => (
            <button
              key={f.id}
              onClick={() => { setStatusFilter(f.id); setPage(1); }}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                statusFilter === f.id ? 'bg-gray-900 text-white' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>
        <select
          value={sort}
          onChange={e => { setSort(e.target.value); setPage(1); }}
          className="px-3 py-2 text-xs font-medium text-gray-500 bg-white border border-gray-200 rounded-lg focus:outline-none focus:border-blue-500"
        >
          <option value="created_at_desc">最新创建</option>
          <option value="created_at_asc">最早创建</option>
          <option value="email_asc">邮箱 A-Z</option>
          <option value="email_desc">邮箱 Z-A</option>
          <option value="updated_at_desc">最近更新</option>
        </select>
        <button className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-gray-500 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
          <IconFilter size={14} /> 筛选
        </button>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        {loading ? (
          <div className="p-6 space-y-4">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex items-center gap-4 animate-pulse">
                <div className="w-8 h-8 bg-gray-200 rounded-full" />
                <div className="flex-1 space-y-2">
                  <div className="h-4 bg-gray-200 rounded w-32" />
                  <div className="h-3 bg-gray-200 rounded w-48" />
                </div>
              </div>
            ))}
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-200">
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">用户</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">角色</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">租户</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">状态</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">邮箱验证</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">最近登录</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {users.map((user) => (
                    <tr
                      key={user.id}
                      className="hover:bg-gray-50 transition-colors cursor-pointer"
                      onClick={() => openUserDrawer(user)}
                    >
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center">
                            <span className="text-xs font-medium text-gray-600">{(user.display_name || user.email).charAt(0)}</span>
                          </div>
                          <div>
                            <p className="text-sm font-medium text-gray-800">{user.display_name || user.email}</p>
                            <p className="text-xs text-gray-400">{user.email}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-700">{user.role}</td>
                      <td className="px-6 py-4 text-sm text-gray-700">{user.tenant}</td>
                      <td className="px-6 py-4"><StatusBadge status={user.status} /></td>
                      <td className="px-6 py-4">
                        {user.email_verified ? (
                          <span className="inline-flex items-center gap-1 text-xs text-emerald-600">
                            <IconCheckCircle size={12} /> 已验证
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-xs text-amber-600">
                            <IconClock size={12} /> 未验证
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-500">{user.last_login || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="px-6 py-3 border-t border-gray-200 flex items-center justify-between">
              <span className="text-xs text-gray-400">显示 {users.length} 条，共 {total} 条</span>
              <div className="flex items-center gap-1">
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} className="px-3 py-1.5 text-xs text-gray-500 bg-gray-100 rounded-md disabled:opacity-50">上一页</button>
                <span className="px-3 py-1.5 text-xs font-medium bg-gray-900 text-white rounded-md">{page}</span>
                <button onClick={() => setPage(p => p + 1)} disabled={users.length < 20} className="px-3 py-1.5 text-xs text-gray-500 hover:bg-gray-100 rounded-md disabled:opacity-50">下一页</button>
              </div>
            </div>
          </>
        )}
      </div>

      <Drawer isOpen={drawerOpen} onClose={() => setDrawerOpen(false)} title="用户详情" width="420px">
        {selectedUser && (
          <div className="space-y-6">
            <div className="flex items-center gap-4">
              <div className="w-14 h-14 rounded-full bg-gray-200 flex items-center justify-center">
                <span className="text-lg font-medium text-gray-600">{(selectedUser.display_name || selectedUser.email).charAt(0)}</span>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900">{selectedUser.display_name || selectedUser.email}</h3>
                <p className="text-sm text-gray-400">{selectedUser.email}</p>
              </div>
            </div>

            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-50 rounded-lg p-3">
                  <p className="text-[10px] font-medium text-gray-400 uppercase tracking-wider mb-1">状态</p>
                  <StatusBadge status={selectedUser.status} />
                </div>
                <div className="bg-gray-50 rounded-lg p-3">
                  <p className="text-[10px] font-medium text-gray-400 uppercase tracking-wider mb-1">角色</p>
                  <p className="text-sm font-medium text-gray-800">{selectedUser.role}</p>
                </div>
              </div>
              <div className="bg-gray-50 rounded-lg p-3">
                <p className="text-[10px] font-medium text-gray-400 uppercase tracking-wider mb-1">所属租户</p>
                <p className="text-sm font-medium text-gray-800">{selectedUser.tenant}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-50 rounded-lg p-3">
                  <p className="text-[10px] font-medium text-gray-400 uppercase tracking-wider mb-1">创建时间</p>
                  <p className="text-sm text-gray-700">{selectedUser.created_at}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-3">
                  <p className="text-[10px] font-medium text-gray-400 uppercase tracking-wider mb-1">最近登录</p>
                  <p className="text-sm text-gray-700">{selectedUser.last_login || '从未登录'}</p>
                </div>
              </div>
            </div>

            <div className="border-t border-gray-200 pt-5 space-y-2">
              <p className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-3">操作</p>
              <button onClick={() => handleResetPassword(selectedUser.id)} className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-gray-700 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                <IconRefreshCw size={16} /> 重置密码
              </button>
              {selectedUser.status === 'active' ? (
                <button onClick={() => setShowConfirm({ userId: selectedUser.id, action: 'disable' })} className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-amber-700 bg-amber-50 border border-amber-200 rounded-lg hover:bg-amber-100 transition-colors">
                  <IconLock size={16} /> 禁用用户
                </button>
              ) : (
                <button onClick={() => setShowConfirm({ userId: selectedUser.id, action: 'enable' })} className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-lg hover:bg-emerald-100 transition-colors">
                  <IconCheckCircle size={16} /> 启用用户
                </button>
              )}
            </div>
          </div>
        )}
      </Drawer>

      {showConfirm && (
        <div className="fixed inset-0 z-[95] flex items-center justify-center">
          <div className="absolute inset-0 bg-black/15 backdrop-blur-sm" onClick={() => setShowConfirm(null)} />
          <div className="relative bg-white rounded-xl border border-gray-200 shadow-2xl p-6 w-full max-w-sm">
            <h3 className="text-base font-semibold text-gray-900 mb-2">{showConfirm.action === 'disable' ? '确认禁用用户？' : '确认启用用户？'}</h3>
            <p className="text-sm text-gray-500 mb-5">{showConfirm.action === 'disable' ? '禁用后该用户将无法登录系统。' : '启用后该用户将恢复正常访问权限。'}</p>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setShowConfirm(null)} className="px-4 py-2 text-sm text-gray-500 hover:bg-gray-100 rounded-lg transition-colors">取消</button>
              <button onClick={() => handleStatusChange(showConfirm.userId, showConfirm.action)} className={`px-4 py-2 text-sm text-white rounded-lg transition-colors ${showConfirm.action === 'disable' ? 'bg-amber-600 hover:bg-amber-700' : 'bg-emerald-600 hover:bg-emerald-700'}`}>确认</button>
            </div>
          </div>
        </div>
      )}

      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
}
