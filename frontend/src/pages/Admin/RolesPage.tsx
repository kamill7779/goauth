import { useState, useEffect } from 'react';
import { addRolePermission, getRoles, getPermissions, removeRolePermission } from '../../api/admin';
import { IconShield, IconUsers, IconLock, IconPlus } from '../../components/admin/Icons';
import type { Role, Permission } from '../../types/admin';

export default function RolesPage() {
  const [roles, setRoles] = useState<Role[]>([]);
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [matrixRole, setMatrixRole] = useState<Role | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    loadRolesAndPermissions();
  }, []);

  const loadRolesAndPermissions = () => {
    setLoading(true);
    Promise.allSettled([getRoles(), getPermissions()])
      .then(([rolesResult, permissionsResult]) => {
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

  const resources = [...new Set(permissions.map(p => p.resource))];
  const actions = [...new Set(permissions.map(p => p.action))];

  const getPermId = (resource: string, action: string) =>
    permissions.find(p => p.resource === resource && p.action === action)?.id;

  return (
    <div className="animate-[fadeInUp_0.4s_ease]">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900 mb-1">角色与权限</h1>
          <p className="text-sm text-gray-400">管理角色定义、权限分配和访问控制矩阵</p>
        </div>
        <button className="inline-flex items-center gap-2 px-4 py-2 bg-gray-900 text-white text-sm font-medium rounded-lg hover:bg-gray-800 transition-colors">
          <IconPlus size={16} /> 创建角色
        </button>
      </div>

      {error && (
        <div className="mb-5 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-700">
          {error}。权限矩阵需要后端提供 `/v1/admin/permissions` 后才能完整编辑。
        </div>
      )}

      {loading ? (
        <div className="grid grid-cols-2 gap-5">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="bg-white rounded-xl border border-gray-200 p-5 animate-pulse">
              <div className="h-10 w-10 bg-gray-200 rounded-lg mb-3" />
              <div className="h-5 w-32 bg-gray-200 rounded mb-2" />
              <div className="h-3 w-48 bg-gray-200 rounded" />
            </div>
          ))}
        </div>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-5 mb-8">
            {roles.map((role) => (
              <div
                key={role.id}
                onClick={() => setMatrixRole(matrixRole?.id === role.id ? null : role)}
                className={`bg-white rounded-xl border p-5 cursor-pointer transition-all duration-300 ${
                  matrixRole?.id === role.id ? 'border-blue-500 ring-1 ring-blue-500/20' : 'border-gray-200 hover:border-gray-300'
                }`}
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="w-10 h-10 bg-gray-100 rounded-lg flex items-center justify-center">
                    <IconShield size={18} className="text-gray-500" />
                  </div>
                  <span className="text-xs text-gray-400">{role.tenant_scope}</span>
                </div>
                <h3 className="text-base font-semibold text-gray-900 mb-1">{role.name}</h3>
                <p className="text-xs text-gray-400 mb-4">{role.description}</p>
                <div className="flex items-center gap-4 text-xs text-gray-500">
                  <span className="flex items-center gap-1"><IconUsers size={12} /> {role.users_count} 用户</span>
                  <span className="flex items-center gap-1"><IconLock size={12} /> {role.permissions_count} 权限</span>
                </div>
              </div>
            ))}
          </div>

          {matrixRole && (
            <div className="bg-white rounded-xl border border-gray-200 overflow-hidden animate-[fadeInUp_0.4s_ease]">
              <div className="px-5 py-4 border-b border-gray-200 flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-semibold text-gray-800">权限矩阵 · {matrixRole.name}</h2>
                  <p className="text-xs text-gray-400 mt-0.5">勾选以分配或移除权限</p>
                </div>
                <button onClick={() => setMatrixRole(null)} className="p-1.5 hover:bg-gray-100 rounded-lg transition-colors">
                  <span className="text-gray-400 text-lg">×</span>
                </button>
              </div>
              {permissions.length === 0 ? (
                <div className="px-5 py-10 text-center text-sm text-gray-400">
                  暂无真实权限字典数据。
                </div>
              ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-200 bg-gray-50">
                      <th className="text-left px-5 py-3 text-xs font-semibold text-gray-500">Resource</th>
                      {actions.map(a => (
                        <th key={a} className="text-center px-3 py-3 text-[10px] font-semibold text-gray-400 uppercase">{a}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {resources.map((resource) => (
                      <tr key={resource} className="hover:bg-gray-50 transition-colors">
                        <td className="px-5 py-3 text-sm font-mono text-gray-700">{resource}</td>
                        {actions.map((action) => {
                          const permId = getPermId(resource, action);
                          const isChecked = Boolean(permId && matrixRole.permission_ids.includes(permId));
                          return (
                            <td key={action} className="px-3 py-3 text-center">
                              <button
                                disabled={!permId}
                                onClick={() => permId && togglePermission(matrixRole, permId, isChecked)}
                                className={`w-5 h-5 rounded border-2 flex items-center justify-center transition-colors ${
                                  isChecked ? 'bg-blue-600 border-blue-600' : 'border-gray-300 hover:border-gray-400 disabled:border-gray-200 disabled:bg-gray-50'
                                }`}
                              >
                                {isChecked && <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3" strokeLinecap="round"><path d="M20 6 9 17l-5-5"/></svg>}
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
    </div>
  );
}
