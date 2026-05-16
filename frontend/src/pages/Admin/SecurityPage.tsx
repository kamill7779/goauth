import { useEffect, useState } from 'react';
import { getAccessOverview } from '../../api/admin';
import type {
  AccessOverviewPayload,
  AccessOverviewRisk,
  AccessOverviewTenant,
} from '../../types/admin';
import {
  IconAlertTriangle,
  IconBuilding,
  IconKey,
  IconRefreshCw,
  IconShield,
} from '../../components/admin/Icons';

type AccessSeverity = 'ok' | 'warning' | 'error';

export interface AccessSummaryCard {
  label: string;
  value: string;
  description: string;
  severity: AccessSeverity;
  readOnly: true;
}

export interface TenantAccessRow {
  id: number;
  name: string;
  slug: string;
  statusLabel: string;
  statusTone: AccessSeverity;
  members: string;
  rbac: string;
  oauthClients: string;
}

export interface AccessRiskRow {
  code: string;
  title: string;
  message: string;
  target: string;
  severity: AccessSeverity;
  severityLabel: string;
}

export function buildAccessSummaryCards(
  overview: Pick<AccessOverviewPayload, 'summary'> & { risks?: Array<{ severity?: string }> },
): AccessSummaryCard[] {
  const risks = overview.risks ?? [];
  const errorCount = risks.filter(risk => risk.severity === 'error').length;
  const warningCount = risks.filter(risk => risk.severity === 'warning').length;
  const riskSeverity: AccessSeverity = errorCount > 0 ? 'error' : warningCount > 0 ? 'warning' : 'ok';

  return [
    {
      label: '活跃租户',
      value: `${overview.summary.active_tenants} / ${overview.summary.total_tenants}`,
      description: '启用租户 / 全部租户',
      severity: 'ok',
      readOnly: true,
    },
    {
      label: '活跃成员',
      value: `${overview.summary.active_members}`,
      description: '当前可参与授权的成员',
      severity: 'ok',
      readOnly: true,
    },
    {
      label: '角色 / 权限',
      value: `${overview.summary.roles} / ${overview.summary.permissions}`,
      description: 'RBAC 规则覆盖',
      severity: 'ok',
      readOnly: true,
    },
    {
      label: '风险',
      value: `${risks.length}`,
      description: `${errorCount} 错误 · ${warningCount} 警告`,
      severity: riskSeverity,
      readOnly: true,
    },
  ];
}

export function buildTenantAccessRows(tenants: AccessOverviewTenant[]): TenantAccessRow[] {
  return tenants.map(tenant => ({
    id: tenant.id,
    name: tenant.name,
    slug: tenant.slug,
    statusLabel: tenant.status === 'active' ? '启用' : tenant.status === 'disabled' ? '停用' : tenant.status,
    statusTone: tenant.status === 'active' ? 'ok' : 'warning',
    members: `${tenant.members_count}`,
    rbac: `${tenant.roles_count} / ${tenant.permissions_count}`,
    oauthClients: `${tenant.oauth_clients_count}`,
  }));
}

export function buildAccessRiskRows(risks: AccessOverviewRisk[]): AccessRiskRow[] {
  return risks.map(risk => ({
    code: risk.code,
    title: riskTitle(risk.code),
    message: risk.message || risk.code,
    target: risk.target || '-',
    severity: risk.severity === 'error' ? 'error' : risk.severity === 'warning' ? 'warning' : 'ok',
    severityLabel: risk.severity === 'error' ? '错误' : risk.severity === 'warning' ? '警告' : '提示',
  }));
}

function riskTitle(code: string): string {
  const titles: Record<string, string> = {
    default_tenant_missing: '默认入组租户不存在',
    default_tenant_unavailable: '默认入组租户不可用',
    role_without_permissions: '角色没有权限',
    active_tenant_without_roles: '启用租户没有角色',
    auto_provision_tenant_unavailable: '自动入组租户不可用',
  };
  return titles[code] ?? code;
}

function severityClass(severity: AccessSeverity): string {
  if (severity === 'error') {
    return 'border-danger bg-danger-soft text-danger';
  }
  if (severity === 'warning') {
    return 'border-warn bg-warn-soft text-warn';
  }
  return 'border-ok bg-ok-soft text-ok';
}

function summaryClass(severity: AccessSeverity): string {
  if (severity === 'error') {
    return 'border-danger bg-danger-soft text-danger';
  }
  if (severity === 'warning') {
    return 'border-warn bg-warn-soft text-warn';
  }
  return 'border-line bg-surface-solid text-ink';
}

export default function SecurityPage() {
  const [overview, setOverview] = useState<AccessOverviewPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadOverview = async () => {
    setLoading(true);
    setError('');
    try {
      setOverview(await getAccessOverview());
    } catch (err) {
      setError(err instanceof Error ? err.message : '加载权限中心失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadOverview();
  }, []);

  const summaryCards = overview ? buildAccessSummaryCards(overview) : [];
  const tenantRows = overview ? buildTenantAccessRows(overview.tenants) : [];
  const riskRows = overview ? buildAccessRiskRows(overview.risks) : [];

  return (
    <div className="animate-[fadeInUp_0.4s_ease]">
      <div className="mb-8 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-ink mb-1">权限中心</h1>
          <p className="text-sm text-ink-tertiary">租户、成员、角色、权限和 OAuth Client 的只读运行总览</p>
        </div>
        <button
          onClick={loadOverview}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-lg border border-line bg-surface-solid px-4 py-2 text-sm font-medium text-ink-secondary transition-colors hover:bg-surface-hover disabled:opacity-50"
        >
          <IconRefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          刷新
        </button>
      </div>

      {error && (
        <div className="mb-5 max-w-2xl rounded-xl border border-danger bg-danger-soft px-4 py-3 text-sm text-danger">
          {error}
        </div>
      )}

      {loading && (
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {Array.from({ length: 4 }).map((_, index) => (
              <div key={index} className="h-24 rounded-xl border border-line bg-surface-solid animate-pulse" />
            ))}
          </div>
          <div className="h-72 rounded-[20px] border border-line bg-surface-solid animate-pulse" />
        </div>
      )}

      {!loading && overview && (
        <div className="space-y-6">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {summaryCards.map(card => (
              <div key={card.label} className={`rounded-xl border px-4 py-3 ${summaryClass(card.severity)}`}>
                <p className="text-xs font-medium opacity-80">{card.label}</p>
                <p className="mt-1 text-2xl font-semibold">{card.value}</p>
                <p className="mt-1 text-xs opacity-75">{card.description}</p>
              </div>
            ))}
          </div>

          <div className="grid gap-6 xl:grid-cols-[minmax(0,0.9fr)_minmax(420px,1.1fr)]">
            <section className="rounded-[20px] border border-line bg-surface-solid overflow-hidden">
              <div className="flex items-center justify-between border-b border-line bg-surface-muted px-5 py-3.5">
                <div className="flex items-center gap-2">
                  <IconAlertTriangle size={16} className="text-ink-tertiary" />
                  <h2 className="text-sm font-semibold text-ink">风险提示</h2>
                </div>
                <span className="text-[11px] font-medium text-ink-tertiary">{riskRows.length} 项</span>
              </div>
              {riskRows.length === 0 ? (
                <div className="px-5 py-8 text-sm text-ink-tertiary">暂无权限配置风险。</div>
              ) : (
                <div className="divide-y divide-line">
                  {riskRows.map(risk => (
                    <div key={`${risk.code}:${risk.target}`} className="px-5 py-4">
                      <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0">
                          <p className="text-sm font-medium text-ink">{risk.title}</p>
                          <p className="mt-1 text-xs leading-5 text-ink-tertiary">{risk.message}</p>
                          <code className="mt-2 inline-block max-w-full truncate rounded-md bg-surface-hover px-2 py-1 text-[11px] text-ink-secondary">
                            {risk.target}
                          </code>
                        </div>
                        <span className={`shrink-0 rounded-lg border px-2.5 py-1 text-xs font-medium ${severityClass(risk.severity)}`}>
                          {risk.severityLabel}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>

            <section className="rounded-[20px] border border-line bg-surface-solid overflow-hidden">
              <div className="flex items-center justify-between border-b border-line bg-surface-muted px-5 py-3.5">
                <div className="flex items-center gap-2">
                  <IconShield size={16} className="text-ink-tertiary" />
                  <h2 className="text-sm font-semibold text-ink">默认入组</h2>
                </div>
                <span className="text-[11px] font-medium text-ink-tertiary">
                  {overview.summary.default_membership_slugs} 个 slug
                </span>
              </div>
              <div className="divide-y divide-line">
                {overview.default_memberships.length === 0 ? (
                  <div className="px-5 py-8 text-sm text-ink-tertiary">未配置 DEFAULT_MEMBER_TENANT_SLUGS。</div>
                ) : overview.default_memberships.map(item => (
                  <div key={item.slug} className="flex items-center justify-between gap-4 px-5 py-4">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium text-ink">{item.slug}</p>
                      <p className="mt-0.5 text-xs text-ink-tertiary">DEFAULT_MEMBER_TENANT_SLUGS</p>
                    </div>
                    <span className={`rounded-lg border px-2.5 py-1 text-xs font-medium ${severityClass(item.found && item.status === 'active' ? 'ok' : item.found ? 'warning' : 'error')}`}>
                      {item.found ? (item.status === 'active' ? '可用' : '不可用') : '缺失'}
                    </span>
                  </div>
                ))}
              </div>
            </section>
          </div>

          <section className="rounded-[20px] border border-line bg-surface-solid overflow-hidden">
            <div className="flex items-center justify-between border-b border-line bg-surface-muted px-5 py-3.5">
              <div className="flex items-center gap-2">
                <IconBuilding size={16} className="text-ink-tertiary" />
                <h2 className="text-sm font-semibold text-ink">租户访问地图</h2>
              </div>
              <span className="text-[11px] font-medium text-ink-tertiary">{tenantRows.length} 个租户</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-line">
                    <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-ink-tertiary">租户</th>
                    <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-ink-tertiary">状态</th>
                    <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-ink-tertiary">成员</th>
                    <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-ink-tertiary">角色 / 权限</th>
                    <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-ink-tertiary">OAuth Client</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {tenantRows.map(row => (
                    <tr key={row.id} className="transition-colors hover:bg-surface-hover">
                      <td className="px-5 py-4">
                        <p className="text-sm font-medium text-ink">{row.name}</p>
                        <p className="mt-0.5 text-xs text-ink-tertiary">{row.slug}</p>
                      </td>
                      <td className="px-5 py-4">
                        <span className={`rounded-lg border px-2.5 py-1 text-xs font-medium ${severityClass(row.statusTone)}`}>
                          {row.statusLabel}
                        </span>
                      </td>
                      <td className="px-5 py-4 text-sm text-ink-secondary">{row.members}</td>
                      <td className="px-5 py-4 text-sm text-ink-secondary">{row.rbac}</td>
                      <td className="px-5 py-4 text-sm text-ink-secondary">{row.oauthClients}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="rounded-[20px] border border-line bg-surface-solid overflow-hidden">
            <div className="flex items-center justify-between border-b border-line bg-surface-muted px-5 py-3.5">
              <div className="flex items-center gap-2">
                <IconKey size={16} className="text-ink-tertiary" />
                <h2 className="text-sm font-semibold text-ink">OAuth Client 自动入组</h2>
              </div>
              <span className="text-[11px] font-medium text-ink-tertiary">
                {overview.summary.auto_provision_clients} / {overview.summary.oauth_clients}
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-line">
                    <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-ink-tertiary">Client</th>
                    <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-ink-tertiary">租户</th>
                    <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-ink-tertiary">自动入组</th>
                    <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-ink-tertiary">Scopes</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {overview.oauth_clients.map(client => (
                    <tr key={client.client_id} className="transition-colors hover:bg-surface-hover">
                      <td className="px-5 py-4">
                        <p className="text-sm font-medium text-ink">{client.name}</p>
                        <p className="mt-0.5 text-xs text-ink-tertiary">{client.client_id}</p>
                      </td>
                      <td className="px-5 py-4">
                        <p className="text-sm text-ink-secondary">{client.tenant_slug || '-'}</p>
                        <p className="mt-0.5 text-xs text-ink-tertiary">{client.tenant_status || '-'}</p>
                      </td>
                      <td className="px-5 py-4">
                        <span className={`rounded-lg border px-2.5 py-1 text-xs font-medium ${severityClass(client.auto_provision_members ? 'warning' : 'ok')}`}>
                          {client.auto_provision_members ? '开启' : '关闭'}
                        </span>
                      </td>
                      <td className="px-5 py-4">
                        <div className="flex max-w-[360px] flex-wrap gap-1.5">
                          {client.allowed_scopes.length === 0 ? (
                            <span className="text-xs text-ink-tertiary">-</span>
                          ) : client.allowed_scopes.map(scope => (
                            <span key={scope} className="rounded-md bg-surface-hover px-2 py-1 text-[11px] font-medium text-ink-secondary">
                              {scope}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
