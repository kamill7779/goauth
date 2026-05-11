import { useState, useEffect, useCallback } from 'react';
import { getTenants } from '../../api/admin';
import StatusBadge from '../../components/admin/StatusBadge';
import Drawer from '../../components/admin/Drawer';
import { IconSearch, IconPlus, IconBuilding, IconUsers, IconShield, IconChevronRight } from '../../components/admin/Icons';
import type { Tenant } from '../../types/admin';

export default function TenantsPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [selectedTenant, setSelectedTenant] = useState<Tenant | null>(null);
  const [error, setError] = useState('');

  const fetchTenants = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getTenants({ search: searchQuery || undefined });
      setTenants(res.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : '租户接口暂不可用');
      setTenants([]);
    } finally {
      setLoading(false);
    }
  }, [searchQuery]);

  useEffect(() => {
    fetchTenants();
  }, [fetchTenants]);

  return (
    <div className="animate-[fadeInUp_0.4s_ease]">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-semibold text-ink mb-1">租户管理</h1>
          <p className="text-sm text-ink-tertiary">管理多租户架构中的租户、成员和接入策略</p>
        </div>
        <button className="inline-flex items-center gap-2 px-4 py-2 bg-ink text-ink-inverse text-sm font-medium rounded-lg hover:opacity-90 transition-opacity">
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
          {tenants.map((tenant) => (
            <div
              key={tenant.id}
              onClick={() => { setSelectedTenant(tenant); setDrawerOpen(true); }}
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
              <button className="w-full flex items-center justify-center gap-2 px-4 py-2.5 text-sm text-ink-secondary bg-surface-solid border border-line rounded-lg hover:bg-surface-hover transition-colors mb-2">
                <IconUsers size={16} /> 查看成员列表
              </button>
              <button className="w-full flex items-center justify-center gap-2 px-4 py-2.5 text-sm text-ink-secondary bg-surface-solid border border-line rounded-lg hover:bg-surface-hover transition-colors">
                <IconPlus size={16} /> 邀请成员
              </button>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}
