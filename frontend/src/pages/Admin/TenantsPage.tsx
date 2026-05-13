import { FormEvent, useCallback, useEffect, useState } from 'react';
import { addTenantMember, createTenant, getTenants, getUsers } from '../../api/admin';
import Drawer from '../../components/admin/Drawer';
import { IconBuilding, IconChevronRight, IconPlus, IconSearch, IconShield, IconUsers } from '../../components/admin/Icons';
import StatusBadge from '../../components/admin/StatusBadge';
import Toast from '../../components/admin/Toast';
import type { Tenant, User } from '../../types/admin';

const initialCreateForm = {
  name: '',
  slug: '',
  status: 'active',
};

const ASSIGNABLE_USERS_PAGE_SIZE = 100;
const ASSIGNABLE_USERS_SORT = 'username_asc';

type UserPageLoader = (params?: Parameters<typeof getUsers>[0]) => ReturnType<typeof getUsers>;

export async function loadAssignableUsers(fetchUsers: UserPageLoader = getUsers): Promise<User[]> {
  const users: User[] = [];
  let page = 1;

  for (;;) {
    const response = await fetchUsers({
      page,
      page_size: ASSIGNABLE_USERS_PAGE_SIZE,
      sort: ASSIGNABLE_USERS_SORT,
    });
    users.push(...response.data);

    const reachedTotal = response.total > 0 && users.length >= response.total;
    if (response.data.length < ASSIGNABLE_USERS_PAGE_SIZE || reachedTotal) {
      return users;
    }
    page += 1;
  }
}

export default function TenantsPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [assignableUsers, setAssignableUsers] = useState<User[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [createSubmitting, setCreateSubmitting] = useState(false);
  const [memberSubmitting, setMemberSubmitting] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [createDrawerOpen, setCreateDrawerOpen] = useState(false);
  const [selectedTenant, setSelectedTenant] = useState<Tenant | null>(null);
  const [selectedUserId, setSelectedUserId] = useState('');
  const [createForm, setCreateForm] = useState(initialCreateForm);
  const [error, setError] = useState('');
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  const fetchTenants = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getTenants({ search: searchQuery || undefined });
      setTenants(res.data);
      setSelectedTenant(current => current ? res.data.find(tenant => tenant.id === current.id) ?? current : null);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : '租户接口暂不可用');
      setTenants([]);
    } finally {
      setLoading(false);
    }
  }, [searchQuery]);

  const fetchAssignableUsers = useCallback(async () => {
    try {
      setAssignableUsers(await loadAssignableUsers());
    } catch (err) {
      setToast({ message: err instanceof Error ? err.message : '用户列表加载失败', type: 'error' });
    }
  }, []);

  useEffect(() => {
    fetchTenants();
  }, [fetchTenants]);

  useEffect(() => {
    if (!drawerOpen || !selectedTenant) {
      return;
    }
    fetchAssignableUsers();
  }, [drawerOpen, fetchAssignableUsers, selectedTenant]);

  const handleCreateTenant = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setCreateSubmitting(true);
    try {
      const tenant = await createTenant(createForm);
      setCreateDrawerOpen(false);
      setCreateForm(initialCreateForm);
      setToast({ message: '租户已创建', type: 'success' });
      setSelectedTenant(tenant);
      setDrawerOpen(true);
      fetchTenants();
    } catch (err) {
      setToast({ message: err instanceof Error ? err.message : '创建失败', type: 'error' });
    } finally {
      setCreateSubmitting(false);
    }
  };

  const handleAddMember = async () => {
    if (!selectedTenant) {
      return;
    }
    if (!selectedUserId) {
      setToast({ message: '请先选择用户', type: 'error' });
      return;
    }
    setMemberSubmitting(true);
    try {
      await addTenantMember(selectedTenant.id, Number(selectedUserId));
      setSelectedUserId('');
      setToast({ message: '成员已加入租户', type: 'success' });
      fetchTenants();
    } catch (err) {
      setToast({ message: err instanceof Error ? err.message : '成员添加失败', type: 'error' });
    } finally {
      setMemberSubmitting(false);
    }
  };

  return (
    <div className="animate-[fadeInUp_0.4s_ease]">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-semibold text-ink mb-1">租户管理</h1>
          <p className="text-sm text-ink-tertiary">管理多租户架构中的租户、成员和接入策略</p>
        </div>
        <button
          onClick={() => {
            setCreateForm(initialCreateForm);
            setCreateDrawerOpen(true);
          }}
          className="inline-flex items-center gap-2 px-4 py-2 bg-ink text-ink-inverse text-sm font-medium rounded-lg hover:opacity-90 transition-opacity"
        >
          <IconPlus size={16} /> 创建租户
        </button>
      </div>

      {error && (
        <div className="mb-5 rounded-xl bg-warn-soft px-4 py-3 text-sm text-warn">
          {error}
        </div>
      )}

      <div className="flex items-center gap-3 mb-5">
        <div className="flex-1 relative max-w-md">
          <IconSearch size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-tertiary" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="搜索租户名称..."
            className="w-full pl-10 pr-4 py-2 text-sm bg-surface-solid border border-line rounded-lg focus:outline-none focus:border-brand transition-all text-ink placeholder:text-ink-muted"
          />
        </div>
      </div>

      {loading ? (
        <div className="grid grid-cols-3 gap-5">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="bg-surface-solid rounded-xl border border-line p-5 animate-pulse">
              <div className="h-10 w-10 bg-surface-hover rounded-lg mb-4" />
              <div className="h-5 w-32 bg-surface-hover rounded mb-2" />
              <div className="h-3 w-20 bg-surface-hover rounded mb-4" />
              <div className="h-4 w-40 bg-surface-hover rounded" />
            </div>
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-3 gap-5">
          {tenants.map(tenant => (
            <div
              key={tenant.id}
              onClick={() => {
                setSelectedTenant(tenant);
                setDrawerOpen(true);
              }}
              className="bg-surface-solid rounded-xl border border-line p-5 hover:shadow-soft-md hover:-translate-y-0.5 cursor-pointer transition-all duration-300"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="w-10 h-10 bg-surface-hover rounded-lg flex items-center justify-center">
                  <IconBuilding size={20} className="text-ink-secondary" />
                </div>
                <StatusBadge status={tenant.status} />
              </div>
              <h3 className="text-base font-semibold text-ink mb-1">{tenant.name}</h3>
              <p className="text-xs text-ink-tertiary font-mono mb-4">{tenant.slug}</p>
              <div className="flex items-center gap-4 text-xs text-ink-secondary">
                <span className="flex items-center gap-1"><IconUsers size={12} /> {tenant.members_count} 成员</span>
                <span className="flex items-center gap-1"><IconShield size={12} /> {tenant.roles_count} 角色</span>
                <span>{tenant.oauth_clients_count} 应用</span>
              </div>
              <div className="mt-4 pt-4 border-t border-line flex items-center justify-between">
                <span className="text-[10px] text-ink-tertiary">默认策略: {tenant.default_policy === 'auto_approve' ? '自动批准' : '人工审核'}</span>
                <IconChevronRight size={14} className="text-ink-muted" />
              </div>
            </div>
          ))}
        </div>
      )}

      <Drawer isOpen={createDrawerOpen} onClose={() => setCreateDrawerOpen(false)} title="创建租户" width="420px">
        <form className="space-y-4" onSubmit={handleCreateTenant}>
          <div>
            <label className="block text-xs font-medium text-ink-secondary mb-2">租户名称</label>
            <input
              value={createForm.name}
              onChange={e => setCreateForm(prev => ({ ...prev, name: e.target.value }))}
              className="w-full px-3 py-2 text-sm bg-surface-solid border border-line rounded-lg focus:outline-none focus:border-brand text-ink"
              placeholder="Community Forum"
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-ink-secondary mb-2">Slug</label>
            <input
              value={createForm.slug}
              onChange={e => setCreateForm(prev => ({ ...prev, slug: e.target.value }))}
              className="w-full px-3 py-2 text-sm bg-surface-solid border border-line rounded-lg focus:outline-none focus:border-brand text-ink font-mono"
              placeholder="community-forum"
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
              <option value="trial">trial</option>
              <option value="disabled">disabled</option>
            </select>
          </div>
          <div className="pt-2 flex justify-end gap-3">
            <button type="button" onClick={() => setCreateDrawerOpen(false)} className="px-4 py-2 text-sm text-ink-secondary hover:bg-surface-hover rounded-lg transition-colors">
              取消
            </button>
            <button type="submit" disabled={createSubmitting} className="px-4 py-2 text-sm text-ink-inverse bg-ink rounded-lg hover:opacity-90 transition-opacity disabled:opacity-50">
              {createSubmitting ? '创建中...' : '创建租户'}
            </button>
          </div>
        </form>
      </Drawer>

      <Drawer isOpen={drawerOpen} onClose={() => setDrawerOpen(false)} title="租户详情" width="420px">
        {selectedTenant && (
          <div className="space-y-6">
            <div className="flex items-center gap-4">
              <div className="w-14 h-14 bg-surface-hover rounded-xl flex items-center justify-center">
                <IconBuilding size={24} className="text-ink-secondary" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-ink">{selectedTenant.name}</h3>
                <p className="text-sm font-mono text-ink-tertiary">{selectedTenant.slug}</p>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-surface-hover rounded-lg p-3">
                <p className="text-[10px] font-medium text-ink-tertiary uppercase tracking-wider mb-1">状态</p>
                <StatusBadge status={selectedTenant.status} />
              </div>
              <div className="bg-surface-hover rounded-lg p-3">
                <p className="text-[10px] font-medium text-ink-tertiary uppercase tracking-wider mb-1">角色数</p>
                <p className="text-sm font-medium text-ink">{selectedTenant.roles_count} 个</p>
              </div>
              <div className="bg-surface-hover rounded-lg p-3">
                <p className="text-[10px] font-medium text-ink-tertiary uppercase tracking-wider mb-1">成员数</p>
                <p className="text-sm font-medium text-ink">{selectedTenant.members_count} 人</p>
              </div>
              <div className="bg-surface-hover rounded-lg p-3">
                <p className="text-[10px] font-medium text-ink-tertiary uppercase tracking-wider mb-1">应用数</p>
                <p className="text-sm font-medium text-ink">{selectedTenant.oauth_clients_count} 个</p>
              </div>
              <div className="bg-surface-hover rounded-lg p-3">
                <p className="text-[10px] font-medium text-ink-tertiary uppercase tracking-wider mb-1">默认策略</p>
                <p className="text-sm text-ink-secondary">{selectedTenant.default_policy === 'auto_approve' ? '自动批准' : '人工审核'}</p>
              </div>
            </div>
            <div className="border-t border-line pt-5">
              <p className="text-xs font-medium text-ink-tertiary uppercase tracking-wider mb-3">成员管理</p>
              <div className="space-y-3">
                <select
                  value={selectedUserId}
                  onChange={e => setSelectedUserId(e.target.value)}
                  className="w-full px-3 py-2.5 text-sm bg-surface-solid border border-line rounded-lg focus:outline-none focus:border-brand text-ink"
                >
                  <option value="">选择要加入该租户的用户</option>
                  {assignableUsers.map(user => (
                    <option key={user.id} value={user.id}>
                      {user.username} · {user.email}
                    </option>
                  ))}
                </select>
                <button
                  onClick={handleAddMember}
                  disabled={memberSubmitting || assignableUsers.length === 0}
                  className="w-full flex items-center justify-center gap-2 px-4 py-2.5 text-sm text-ink-inverse bg-ink rounded-lg hover:opacity-90 transition-opacity disabled:opacity-50"
                >
                  <IconPlus size={16} /> {memberSubmitting ? '加入中...' : '加入成员'}
                </button>
              </div>
            </div>
          </div>
        )}
      </Drawer>

      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
}
