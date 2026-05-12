import { FormEvent, useEffect, useState } from 'react';
import { addRolePermission, createRole, getPermissions, getRoles, getTenants, removeRolePermission } from '../../api/admin';
import Drawer from '../../components/admin/Drawer';
import { IconLock, IconPlus, IconShield, IconUsers } from '../../components/admin/Icons';
import Toast from '../../components/admin/Toast';
import type { Permission, Role, Tenant } from '../../types/admin';

const initialCreateForm = {
  tenantId: '',
  name: '',
  code: '',
  description: '',
};

export default function RolesPage() {
  const [roles, setRoles] = useState<Role[]>([]);
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [matrixRole, setMatrixRole] = useState<Role | null>(null);
  const [loading, setLoading] = useState(true);
  const [createSubmitting, setCreateSubmitting] = useState(false);
  const [createDrawerOpen, setCreateDrawerOpen] = useState(false);
  const [createForm, setCreateForm] = useState(initialCreateForm);
  const [error, setError] = useState('');
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  useEffect(() => {
    loadRolesAndPermissions();
  }, []);

  const loadRolesAndPermissions = () => {
    setLoading(true);
    Promise.allSettled([
      getRoles(),
      getPermissions(),
      getTenants({ page: 1, page_size: 100, sort: 'created_at_desc' }),
    ])
      .then(([rolesResult, permissionsResult, tenantsResult]) => {
        if (rolesResult.status === 'fulfilled') {
          setRoles(rolesResult.value);
        } else {
          setError(rolesResult.reason instanceof Error ? rolesResult.reason.message : '角色接口暂不可用');
        }

        if (permissionsResult.status === 'fulfilled') {
          setPermissions(permissionsResult.value);
        } else {
          setError(prev => prev || (permissionsResult.reason instanceof Error ? permissionsResult.reason.message : '权限字典接口暂不可用'));
        }

        if (tenantsResult.status === 'fulfilled') {
          setTenants(tenantsResult.value.data);
          setCreateForm(current => current.tenantId ? current : {
            ...current,
            tenantId: tenantsResult.value.data[0] ? String(tenantsResult.value.data[0].id) : '',
          });
        } else {
          setError(prev => prev || (tenantsResult.reason instanceof Error ? tenantsResult.reason.message : '租户列表加载失败'));
        }
      })
      .finally(() => setLoading(false));
  };

  const syncRole = (roleId: number, updater: (role: Role) => Role) => {
    setRoles(current => current.map(role => role.id === roleId ? updater(role) : role));
    setMatrixRole(current => current?.id === roleId ? updater(current) : current);
  };

  const togglePermission = async (role: Role, permissionId: number, checked: boolean) => {
    try {
      if (checked) {
        await removeRolePermission(role.id, permissionId);
      } else {
        await addRolePermission(role.id, permissionId);
      }
      syncRole(role.id, current => {
        const nextIds = checked
          ? current.permission_ids.filter(id => id !== permissionId)
          : [...new Set([...current.permission_ids, permissionId])];
        return {
          ...current,
          permission_ids: nextIds,
          permissions_count: nextIds.length,
        };
      });
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : '权限更新失败');
    }
  };

  const handleCreateRole = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setCreateSubmitting(true);
    try {
      await createRole({
        tenant_id: Number(createForm.tenantId),
        name: createForm.name,
        code: createForm.code,
        description: createForm.description,
        is_system: false,
      });
      setCreateDrawerOpen(false);
      setCreateForm({
        ...initialCreateForm,
        tenantId: tenants[0] ? String(tenants[0].id) : '',
      });
      setToast({ message: '角色已创建', type: 'success' });
      loadRolesAndPermissions();
    } catch (err) {
      setToast({ message: err instanceof Error ? err.message : '角色创建失败', type: 'error' });
    } finally {
      setCreateSubmitting(false);
    }
  };

  const resources = [...new Set(permissions.map(p => p.resource))];
  const actions = [...new Set(permissions.map(p => p.action))];

  const getPermId = (resource: string, action: string) =>
    permissions.find(p => p.resource === resource && p.action === action)?.id;

  return (
    <div className="animate-[fadeInUp_0.4s_ease]">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-semibold text-ink mb-1">角色与权限</h1>
          <p className="text-sm text-ink-tertiary">管理角色定义、权限分配和访问控制矩阵</p>
        </div>
        <button
          onClick={() => {
            setCreateForm(current => ({
              ...current,
              tenantId: current.tenantId || (tenants[0] ? String(tenants[0].id) : ''),
            }));
            setCreateDrawerOpen(true);
          }}
          disabled={tenants.length === 0}
          className="inline-flex items-center gap-2 px-4 py-2 bg-ink text-ink-inverse text-sm font-medium rounded-lg hover:opacity-90 transition-opacity disabled:opacity-50"
        >
          <IconPlus size={16} /> 创建角色
        </button>
      </div>

      {error && (
        <div className="mb-5 rounded-xl bg-warn-soft px-4 py-3 text-sm text-warn">
          {error}。权限矩阵需要后端提供 `/v1/admin/permissions` 后才能完整编辑。
        </div>
      )}

      {loading ? (
        <div className="grid grid-cols-2 gap-5">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="bg-surface-solid rounded-xl border border-line p-5 animate-pulse">
              <div className="h-10 w-10 bg-surface-hover rounded-lg mb-3" />
              <div className="h-5 w-32 bg-surface-hover rounded mb-2" />
              <div className="h-3 w-48 bg-surface-hover rounded" />
            </div>
          ))}
        </div>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-5 mb-8">
            {roles.map(role => {
              const isSelected = matrixRole?.id === role.id;
              return (
                <div
                  key={role.id}
                  onClick={() => setMatrixRole(isSelected ? null : role)}
                  className="bg-surface-solid rounded-xl border p-5 cursor-pointer transition-all duration-300"
                  style={{
                    borderColor: isSelected ? 'var(--accent)' : 'var(--border)',
                    boxShadow: isSelected ? '0 0 0 3px var(--accent-soft)' : 'none',
                  }}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="w-10 h-10 bg-surface-hover rounded-lg flex items-center justify-center">
                      <IconShield size={18} className="text-ink-secondary" />
                    </div>
                    <span className="text-xs text-ink-tertiary">{role.tenant_scope}</span>
                  </div>
                  <h3 className="text-base font-semibold text-ink mb-1">{role.name}</h3>
                  <p className="text-xs text-ink-tertiary mb-4">{role.description}</p>
                  <div className="flex items-center gap-4 text-xs text-ink-secondary">
                    <span className="flex items-center gap-1"><IconUsers size={12} /> {role.users_count} 用户</span>
                    <span className="flex items-center gap-1"><IconLock size={12} /> {role.permissions_count} 权限</span>
                  </div>
                </div>
              );
            })}
          </div>

          {matrixRole && (
            <div className="bg-surface-solid rounded-xl border border-line overflow-hidden animate-[fadeInUp_0.4s_ease]">
              <div className="px-5 py-4 border-b border-line flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-semibold text-ink">权限矩阵 · {matrixRole.name}</h2>
                  <p className="text-xs text-ink-tertiary mt-0.5">勾选以分配或移除权限</p>
                </div>
                <button onClick={() => setMatrixRole(null)} className="p-1.5 hover:bg-surface-hover rounded-lg transition-colors">
                  <span className="text-ink-tertiary text-lg">×</span>
                </button>
              </div>
              {permissions.length === 0 ? (
                <div className="px-5 py-10 text-center text-sm text-ink-tertiary">
                  暂无真实权限字典数据。
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-line bg-surface-muted">
                        <th className="text-left px-5 py-3 text-xs font-semibold text-ink-secondary">Resource</th>
                        {actions.map(a => (
                          <th key={a} className="text-center px-3 py-3 text-[10px] font-semibold text-ink-tertiary uppercase">{a}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line">
                      {resources.map(resource => (
                        <tr key={resource} className="hover:bg-surface-hover transition-colors">
                          <td className="px-5 py-3 text-sm font-mono text-ink-secondary">{resource}</td>
                          {actions.map(action => {
                            const permId = getPermId(resource, action);
                            const isChecked = Boolean(permId && matrixRole.permission_ids.includes(permId));
                            return (
                              <td key={action} className="px-3 py-3 text-center">
                                <button
                                  disabled={!permId}
                                  onClick={() => permId && togglePermission(matrixRole, permId, isChecked)}
                                  className="w-5 h-5 rounded border-2 flex items-center justify-center transition-colors disabled:opacity-50"
                                  style={{
                                    backgroundColor: isChecked ? 'var(--accent)' : 'transparent',
                                    borderColor: isChecked ? 'var(--accent)' : 'var(--border-strong)',
                                  }}
                                >
                                  {isChecked && <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3" strokeLinecap="round"><path d="M20 6 9 17l-5-5" /></svg>}
                                </button>
                              </td>
                            );
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </>
      )}

      <Drawer isOpen={createDrawerOpen} onClose={() => setCreateDrawerOpen(false)} title="创建角色" width="420px">
        <form className="space-y-4" onSubmit={handleCreateRole}>
          <div>
            <label className="block text-xs font-medium text-ink-secondary mb-2">所属租户</label>
            <select
              value={createForm.tenantId}
              onChange={e => setCreateForm(prev => ({ ...prev, tenantId: e.target.value }))}
              className="w-full px-3 py-2 text-sm bg-surface-solid border border-line rounded-lg focus:outline-none focus:border-brand text-ink"
              required
            >
              <option value="">选择租户</option>
              {tenants.map(tenant => (
                <option key={tenant.id} value={tenant.id}>
                  {tenant.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-ink-secondary mb-2">角色名称</label>
            <input
              value={createForm.name}
              onChange={e => setCreateForm(prev => ({ ...prev, name: e.target.value }))}
              className="w-full px-3 py-2 text-sm bg-surface-solid border border-line rounded-lg focus:outline-none focus:border-brand text-ink"
              placeholder="Moderator"
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-ink-secondary mb-2">角色编码</label>
            <input
              value={createForm.code}
              onChange={e => setCreateForm(prev => ({ ...prev, code: e.target.value }))}
              className="w-full px-3 py-2 text-sm bg-surface-solid border border-line rounded-lg focus:outline-none focus:border-brand text-ink font-mono"
              placeholder="moderator"
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-ink-secondary mb-2">描述</label>
            <textarea
              value={createForm.description}
              onChange={e => setCreateForm(prev => ({ ...prev, description: e.target.value }))}
              className="w-full min-h-24 px-3 py-2 text-sm bg-surface-solid border border-line rounded-lg focus:outline-none focus:border-brand text-ink resize-y"
              placeholder="Moderates content and community workflows"
              required
            />
          </div>
          <div className="pt-2 flex justify-end gap-3">
            <button type="button" onClick={() => setCreateDrawerOpen(false)} className="px-4 py-2 text-sm text-ink-secondary hover:bg-surface-hover rounded-lg transition-colors">
              取消
            </button>
            <button type="submit" disabled={createSubmitting} className="px-4 py-2 text-sm text-ink-inverse bg-ink rounded-lg hover:opacity-90 transition-opacity disabled:opacity-50">
              {createSubmitting ? '创建中...' : '创建角色'}
            </button>
          </div>
        </form>
      </Drawer>

      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
}
