import { FormEvent, useCallback, useEffect, useState } from 'react';
import { createUser, disableUser, enableUser, getUsers, resetPassword } from '../../api/admin';
import Drawer from '../../components/admin/Drawer';
import { IconCheckCircle, IconClock, IconFilter, IconLock, IconPlus, IconRefreshCw, IconSearch } from '../../components/admin/Icons';
import StatusBadge from '../../components/admin/StatusBadge';
import Toast from '../../components/admin/Toast';
import type { User } from '../../types/admin';

const initialCreateForm = {
  username: '',
  nickname: '',
  email: '',
  password: '',
  status: 'active',
};

export function planUserListRefreshAfterCreate(currentPage: number) {
  const nextPage = 1;
  return {
    nextPage,
    shouldFetchImmediately: currentPage === nextPage,
  };
}

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [total, setTotal] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sort, setSort] = useState('created_at_desc');
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [createSubmitting, setCreateSubmitting] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [createDrawerOpen, setCreateDrawerOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [createForm, setCreateForm] = useState(initialCreateForm);
  const [showConfirm, setShowConfirm] = useState<{ userId: number; action: string } | null>(null);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  const fetchUsers = useCallback(async (pageOverride = page) => {
    setLoading(true);
    try {
      const res = await getUsers({
        search: searchQuery || undefined,
        status: statusFilter === 'all' ? undefined : statusFilter,
        sort,
        page: pageOverride,
        page_size: 20,
      });
      setUsers(res.data);
      setTotal(res.total);
    } catch (err) {
      setToast({ message: err instanceof Error ? err.message : '加载失败', type: 'error' });
    } finally {
      setLoading(false);
    }
  }, [page, searchQuery, sort, statusFilter]);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  const openUserDrawer = (user: User) => {
    setSelectedUser(user);
    setDrawerOpen(true);
  };

  const handleStatusChange = async (userId: number, action: string) => {
    try {
      if (action === 'disable') {
        await disableUser(userId);
      } else {
        await enableUser(userId);
      }
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

  const handleCreateUser = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setCreateSubmitting(true);
    try {
      await createUser({
        username: createForm.username,
        nickname: createForm.nickname,
        email: createForm.email,
        password: createForm.password,
        status: createForm.status,
      } as Parameters<typeof createUser>[0]);
      setCreateDrawerOpen(false);
      setCreateForm(initialCreateForm);
      setToast({ message: '用户已创建', type: 'success' });
      const refreshPlan = planUserListRefreshAfterCreate(page);
      setPage(refreshPlan.nextPage);
      if (refreshPlan.shouldFetchImmediately) {
        await fetchUsers(refreshPlan.nextPage);
      }
    } catch (err) {
      setToast({ message: err instanceof Error ? err.message : '创建失败', type: 'error' });
    } finally {
      setCreateSubmitting(false);
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
          <h1 className="text-2xl font-semibold text-ink mb-1">用户管理</h1>
          <p className="text-sm text-ink-tertiary">管理系统用户、租户成员和权限分配</p>
        </div>
        <button
          onClick={() => {
            setCreateForm(initialCreateForm);
            setCreateDrawerOpen(true);
          }}
          className="inline-flex items-center gap-2 px-4 py-2 bg-ink text-ink-inverse text-sm font-medium rounded-lg hover:opacity-90 transition-opacity"
        >
          <IconPlus size={16} /> 创建用户
        </button>
      </div>

      <div className="flex items-center gap-3 mb-5">
        <div className="flex-1 relative max-w-md">
          <IconSearch size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-tertiary" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => {
              setSearchQuery(e.target.value);
              setPage(1);
            }}
            placeholder="搜索 username、昵称或邮箱..."
            className="w-full pl-10 pr-4 py-2 text-sm bg-surface-solid border border-line rounded-lg focus:outline-none focus:border-brand transition-all text-ink placeholder:text-ink-muted"
          />
        </div>
        <div className="flex items-center gap-1 bg-surface-solid border border-line rounded-lg p-0.5">
          {filters.map(f => (
            <button
              key={f.id}
              onClick={() => {
                setStatusFilter(f.id);
                setPage(1);
              }}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                statusFilter === f.id ? 'bg-ink text-ink-inverse' : 'text-ink-secondary hover:text-ink hover:bg-surface-hover'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>
        <select
          value={sort}
          onChange={e => {
            setSort(e.target.value);
            setPage(1);
          }}
          className="px-3 py-2 text-xs font-medium text-ink-secondary bg-surface-solid border border-line rounded-lg focus:outline-none focus:border-brand"
        >
          <option value="created_at_desc">最新创建</option>
          <option value="created_at_asc">最早创建</option>
          <option value="username_asc">用户名 A-Z</option>
          <option value="username_desc">用户名 Z-A</option>
          <option value="email_asc">邮箱 A-Z</option>
          <option value="email_desc">邮箱 Z-A</option>
          <option value="updated_at_desc">最近更新</option>
        </select>
        <button className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-ink-secondary bg-surface-solid border border-line rounded-lg hover:bg-surface-hover transition-colors">
          <IconFilter size={14} /> 筛选
        </button>
      </div>

      <div className="bg-surface-solid rounded-[20px] border border-line overflow-hidden">
        {loading ? (
          <div className="p-6 space-y-4">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex items-center gap-4 animate-pulse">
                <div className="w-8 h-8 bg-surface-hover rounded-full" />
                <div className="flex-1 space-y-2">
                  <div className="h-4 bg-surface-hover rounded w-32" />
                  <div className="h-3 bg-surface-hover rounded w-48" />
                </div>
              </div>
            ))}
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-line">
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-ink-tertiary uppercase tracking-wider">用户</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-ink-tertiary uppercase tracking-wider">角色</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-ink-tertiary uppercase tracking-wider">租户</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-ink-tertiary uppercase tracking-wider">状态</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-ink-tertiary uppercase tracking-wider">邮箱验证</th>
                    <th className="text-left px-6 py-3.5 text-xs font-semibold text-ink-tertiary uppercase tracking-wider">最近登录</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {users.map(user => (
                    <tr
                      key={user.id}
                      className="hover:bg-surface-hover transition-colors cursor-pointer"
                      onClick={() => openUserDrawer(user)}
                    >
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-full bg-surface-hover flex items-center justify-center">
                            <span className="text-xs font-medium text-ink-secondary">{(user.nickname || user.username || user.email).charAt(0)}</span>
                          </div>
                          <div>
                            <p className="text-sm font-medium text-ink">{user.username}</p>
                            <p className="text-xs text-ink-secondary">{user.nickname}</p>
                            <p className="text-xs text-ink-tertiary">{user.email}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-ink-secondary">{user.role}</td>
                      <td className="px-6 py-4 text-sm text-ink-secondary">{user.tenant}</td>
                      <td className="px-6 py-4"><StatusBadge status={user.status} /></td>
                      <td className="px-6 py-4">
                        {user.email_verified ? (
                          <span className="inline-flex items-center gap-1 text-xs text-ok">
                            <IconCheckCircle size={12} /> 已验证
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-xs text-warn">
                            <IconClock size={12} /> 未验证
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-sm text-ink-secondary">{user.last_login || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="px-6 py-3 border-t border-line flex items-center justify-between">
              <span className="text-xs text-ink-tertiary">显示 {users.length} 条，共 {total} 条</span>
              <div className="flex items-center gap-1">
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} className="px-3 py-1.5 text-xs text-ink-secondary bg-surface-hover rounded-md disabled:opacity-50">上一页</button>
                <span className="px-3 py-1.5 text-xs font-medium bg-ink text-ink-inverse rounded-md">{page}</span>
                <button onClick={() => setPage(p => p + 1)} disabled={users.length < 20} className="px-3 py-1.5 text-xs text-ink-secondary hover:bg-surface-hover rounded-md disabled:opacity-50">下一页</button>
              </div>
            </div>
          </>
        )}
      </div>

      <Drawer isOpen={createDrawerOpen} onClose={() => setCreateDrawerOpen(false)} title="创建用户" width="420px">
        <form className="space-y-4" onSubmit={handleCreateUser}>
          <div>
            <label className="block text-xs font-medium text-ink-secondary mb-2">用户名</label>
            <input
              value={createForm.username}
              onChange={e => setCreateForm(prev => ({ ...prev, username: e.target.value }))}
              className="w-full px-3 py-2 text-sm bg-surface-solid border border-line rounded-lg focus:outline-none focus:border-brand text-ink"
              placeholder="member-01"
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-ink-secondary mb-2">昵称</label>
            <input
              value={createForm.nickname}
              onChange={e => setCreateForm(prev => ({ ...prev, nickname: e.target.value }))}
              className="w-full px-3 py-2 text-sm bg-surface-solid border border-line rounded-lg focus:outline-none focus:border-brand text-ink"
              placeholder="展示昵称"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-ink-secondary mb-2">邮箱</label>
            <input
              type="email"
              value={createForm.email}
              onChange={e => setCreateForm(prev => ({ ...prev, email: e.target.value }))}
              className="w-full px-3 py-2 text-sm bg-surface-solid border border-line rounded-lg focus:outline-none focus:border-brand text-ink"
              placeholder="member@example.com"
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-ink-secondary mb-2">初始密码</label>
            <input
              type="password"
              value={createForm.password}
              onChange={e => setCreateForm(prev => ({ ...prev, password: e.target.value }))}
              className="w-full px-3 py-2 text-sm bg-surface-solid border border-line rounded-lg focus:outline-none focus:border-brand text-ink"
              placeholder="至少 8 位"
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-ink-secondary mb-2">状态</label>
            <select
              value={createForm.status}
              onChange={e => setCreateForm(prev => ({ ...prev, status: e.target.value }))}
              className="w-full px-3 py-2 text-sm bg-surface-solid border border-line rounded-lg focus:outline-none focus:border-brand text-ink"
            >
              <option value="active">active</option>
              <option value="disabled">disabled</option>
            </select>
          </div>
          <div className="pt-2 flex justify-end gap-3">
            <button type="button" onClick={() => setCreateDrawerOpen(false)} className="px-4 py-2 text-sm text-ink-secondary hover:bg-surface-hover rounded-lg transition-colors">
              取消
            </button>
            <button type="submit" disabled={createSubmitting} className="px-4 py-2 text-sm text-ink-inverse bg-ink rounded-lg hover:opacity-90 transition-opacity disabled:opacity-50">
              {createSubmitting ? '创建中...' : '创建用户'}
            </button>
          </div>
        </form>
      </Drawer>

      <Drawer isOpen={drawerOpen} onClose={() => setDrawerOpen(false)} title="用户详情" width="420px">
        {selectedUser && (
          <div className="space-y-6">
            <div className="flex items-center gap-4">
              <div className="w-14 h-14 rounded-full bg-surface-hover flex items-center justify-center">
                <span className="text-lg font-medium text-ink-secondary">{(selectedUser.nickname || selectedUser.username || selectedUser.email).charAt(0)}</span>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-ink">{selectedUser.username}</h3>
                <p className="text-sm text-ink-secondary">{selectedUser.nickname}</p>
                <p className="text-sm text-ink-tertiary">{selectedUser.email}</p>
              </div>
            </div>

            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-surface-hover rounded-lg p-3">
                  <p className="text-[10px] font-medium text-ink-tertiary uppercase tracking-wider mb-1">状态</p>
                  <StatusBadge status={selectedUser.status} />
                </div>
                <div className="bg-surface-hover rounded-lg p-3">
                  <p className="text-[10px] font-medium text-ink-tertiary uppercase tracking-wider mb-1">角色</p>
                  <p className="text-sm font-medium text-ink">{selectedUser.role}</p>
                </div>
              </div>
              <div className="bg-surface-hover rounded-lg p-3">
                <p className="text-[10px] font-medium text-ink-tertiary uppercase tracking-wider mb-1">所属租户</p>
                <p className="text-sm font-medium text-ink">{selectedUser.tenant}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-surface-hover rounded-lg p-3">
                  <p className="text-[10px] font-medium text-ink-tertiary uppercase tracking-wider mb-1">创建时间</p>
                  <p className="text-sm text-ink-secondary">{selectedUser.created_at}</p>
                </div>
                <div className="bg-surface-hover rounded-lg p-3">
                  <p className="text-[10px] font-medium text-ink-tertiary uppercase tracking-wider mb-1">最近登录</p>
                  <p className="text-sm text-ink-secondary">{selectedUser.last_login || '从未登录'}</p>
                </div>
              </div>
            </div>

            <div className="border-t border-line pt-5 space-y-2">
              <p className="text-xs font-medium text-ink-tertiary uppercase tracking-wider mb-3">操作</p>
              <button onClick={() => handleResetPassword(selectedUser.id)} className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-ink-secondary bg-surface-solid border border-line rounded-lg hover:bg-surface-hover transition-colors">
                <IconRefreshCw size={16} /> 重置密码
              </button>
              {selectedUser.status === 'active' ? (
                <button onClick={() => setShowConfirm({ userId: selectedUser.id, action: 'disable' })} className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-warn bg-warn-soft rounded-lg hover:opacity-90 transition-opacity">
                  <IconLock size={16} /> 禁用用户
                </button>
              ) : (
                <button onClick={() => setShowConfirm({ userId: selectedUser.id, action: 'enable' })} className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-ok bg-ok-soft rounded-lg hover:opacity-90 transition-opacity">
                  <IconCheckCircle size={16} /> 启用用户
                </button>
              )}
            </div>
          </div>
        )}
      </Drawer>

      {showConfirm && (
        <div className="fixed inset-0 z-[95] flex items-center justify-center">
          <div className="absolute inset-0 backdrop-blur-sm" style={{ background: 'var(--overlay)' }} onClick={() => setShowConfirm(null)} />
          <div className="relative bg-surface-solid rounded-xl border border-line shadow-soft-lg p-6 w-full max-w-sm">
            <h3 className="text-base font-semibold text-ink mb-2">{showConfirm.action === 'disable' ? '确认禁用用户？' : '确认启用用户？'}</h3>
            <p className="text-sm text-ink-secondary mb-5">{showConfirm.action === 'disable' ? '禁用后该用户将无法登录系统。' : '启用后该用户将恢复正常访问权限。'}</p>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setShowConfirm(null)} className="px-4 py-2 text-sm text-ink-secondary hover:bg-surface-hover rounded-lg transition-colors">取消</button>
              <button
                onClick={() => handleStatusChange(showConfirm.userId, showConfirm.action)}
                className="px-4 py-2 text-sm text-white rounded-lg transition-opacity hover:opacity-90"
                style={{ background: showConfirm.action === 'disable' ? 'var(--warning)' : 'var(--success)' }}
              >
                确认
              </button>
            </div>
          </div>
        </div>
      )}

      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
}
