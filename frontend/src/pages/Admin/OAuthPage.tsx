import { useEffect, useState } from 'react';
import {
  createOAuthClient,
  getOAuthClients,
  rotateClientSecret,
  updateOAuthClientStatus,
} from '../../api/admin';
import Drawer from '../../components/admin/Drawer';
import StatusBadge from '../../components/admin/StatusBadge';
import Toast from '../../components/admin/Toast';
import { IconKey, IconPlus, IconRefreshCw } from '../../components/admin/Icons';
import type { CreateOAuthClientInput, OAuthClient } from '../../types/admin';

type ClientStatus = OAuthClient['status'];

type CreateFormState = {
  tenant_id: string;
  client_id: string;
  client_secret: string;
  name: string;
  redirect_uris: string;
  scopes: string;
  token_endpoint_auth_method: CreateOAuthClientInput['token_endpoint_auth_method'];
  auto_provision_members: boolean;
};

type ToastState = {
  message: string;
  type: 'success' | 'error' | 'info';
};

type SecretNotice = {
  clientId: string;
  secret: string;
  source: 'create' | 'rotate';
};

export type RotateSecretOutcome = {
  secretNotice: SecretNotice | null;
  toast: ToastState;
};

const INITIAL_FORM: CreateFormState = {
  tenant_id: '',
  client_id: '',
  client_secret: '',
  name: '',
  redirect_uris: '',
  scopes: 'openid\nprofile\nemail',
  token_endpoint_auth_method: 'client_secret_post',
  auto_provision_members: true,
};

const STATUS_OPTIONS: ClientStatus[] = ['active', 'disabled', 'inactive'];

function parseLines(value: string): string[] {
  return value
    .split(/\r?\n|,/)
    .map(item => item.trim())
    .filter(Boolean);
}

function upsertClient(list: OAuthClient[], next: OAuthClient) {
  const existing = list.some(client => client.client_id === next.client_id);
  if (!existing) {
    return [next, ...list];
  }
  return list.map(client => client.client_id === next.client_id ? next : client);
}

export function applyRotateSecretOutcome({
  currentNotice,
  result,
}: {
  currentNotice: SecretNotice | null;
  result: { client: OAuthClient; client_secret?: string };
}): RotateSecretOutcome {
  if (result.client_secret) {
    return {
      secretNotice: {
        clientId: result.client.client_id,
        secret: result.client_secret,
        source: 'rotate',
      },
      toast: {
        message: `${result.client.client_id} 密钥已轮换`,
        type: 'success',
      },
    };
  }

  return {
    secretNotice: currentNotice?.source === 'rotate' || currentNotice?.source === 'create' ? null : currentNotice,
    toast: {
      message: `${result.client.client_id} 已轮换，但后端未返回新的 client secret，请重新操作。`,
      type: 'error',
    },
  };
}

export default function OAuthPage() {
  const [clients, setClients] = useState<OAuthClient[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [form, setForm] = useState<CreateFormState>(INITIAL_FORM);
  const [formError, setFormError] = useState('');
  const [creating, setCreating] = useState(false);
  const [pendingStatusClientId, setPendingStatusClientId] = useState('');
  const [pendingRotateClientId, setPendingRotateClientId] = useState('');
  const [toast, setToast] = useState<ToastState | null>(null);
  const [secretNotice, setSecretNotice] = useState<SecretNotice | null>(null);

  useEffect(() => {
    getOAuthClients()
      .then(setClients)
      .catch(err => setError(err instanceof Error ? err.message : 'OAuth Client 接口暂不可用'))
      .finally(() => setLoading(false));
  }, []);

  const updateForm = <K extends keyof CreateFormState>(key: K, value: CreateFormState[K]) => {
    setForm(current => ({ ...current, [key]: value }));
  };

  const resetCreateForm = () => {
    setForm(INITIAL_FORM);
    setFormError('');
  };

  const handleCreateClient = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFormError('');

    const tenantID = Number(form.tenant_id);
    const redirectURIs = parseLines(form.redirect_uris);
    const scopes = parseLines(form.scopes);

    if (!Number.isFinite(tenantID) || tenantID <= 0) {
      setFormError('请输入有效的 Tenant ID。');
      return;
    }
    if (!form.client_id.trim() || !form.name.trim() || !form.client_secret.trim()) {
      setFormError('请完整填写 Client ID、名称和 Client Secret。');
      return;
    }
    if (redirectURIs.length === 0) {
      setFormError('至少填写一个回调地址。');
      return;
    }
    if (scopes.length === 0) {
      setFormError('至少填写一个 scope。');
      return;
    }

    setCreating(true);
    try {
      const result = await createOAuthClient({
        tenant_id: tenantID,
        client_id: form.client_id.trim(),
        client_secret: form.client_secret,
        name: form.name.trim(),
        redirect_uris: redirectURIs,
        scopes,
        token_endpoint_auth_method: form.token_endpoint_auth_method,
        auto_provision_members: form.auto_provision_members,
      });
      setClients(current => upsertClient(current, result.client));
      setSecretNotice({
        clientId: result.client.client_id,
        secret: result.client_secret ?? form.client_secret,
        source: 'create',
      });
      setToast({ message: `Client ${result.client.client_id} 已创建`, type: 'success' });
      setDrawerOpen(false);
      resetCreateForm();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : '创建 OAuth Client 失败');
    } finally {
      setCreating(false);
    }
  };

  const handleStatusChange = async (clientId: string, nextStatus: ClientStatus) => {
    setPendingStatusClientId(clientId);
    try {
      const updated = await updateOAuthClientStatus(clientId, nextStatus);
      setClients(current => current.map(client => client.client_id === clientId ? updated : client));
      setToast({ message: `${clientId} 状态已更新为 ${nextStatus}`, type: 'info' });
    } catch (err) {
      setToast({ message: err instanceof Error ? err.message : '更新状态失败', type: 'error' });
    } finally {
      setPendingStatusClientId('');
    }
  };

  const handleRotateSecret = async (clientId: string) => {
    setPendingRotateClientId(clientId);
    try {
      const result = await rotateClientSecret(clientId);
      setClients(current => current.map(client => client.client_id === clientId ? result.client : client));
      const outcome = applyRotateSecretOutcome({
        currentNotice: secretNotice,
        result,
      });
      setSecretNotice(outcome.secretNotice);
      setToast(outcome.toast);
    } catch (err) {
      setSecretNotice(null);
      setToast({ message: err instanceof Error ? err.message : '轮换密钥失败', type: 'error' });
    } finally {
      setPendingRotateClientId('');
    }
  };

  return (
    <div className="animate-[fadeInUp_0.4s_ease]">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="mb-1 text-2xl font-semibold text-ink">OAuth Clients</h1>
          <p className="text-sm text-ink-tertiary">管理 OIDC/OAuth 2.0 客户端、密钥和授权范围</p>
        </div>
        <button
          onClick={() => setDrawerOpen(true)}
          className="inline-flex items-center gap-2 rounded-lg bg-ink px-4 py-2 text-sm font-medium text-ink-inverse transition-opacity hover:opacity-90"
        >
          <IconPlus size={16} /> 注册 Client
        </button>
      </div>

      {secretNotice && (
        <div className="mb-5 rounded-2xl border border-line bg-surface-solid p-5 shadow-soft-sm">
          <div className="mb-3 flex items-start gap-3">
            <div className="mt-0.5 rounded-xl bg-surface-hover p-2 text-ink">
              <IconKey size={16} />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold text-ink">
                {secretNotice.source === 'rotate' ? '新密钥已生成' : 'Client 已创建'}
              </p>
              <p className="mt-1 text-sm leading-6 text-ink-secondary">
                GoAuth 不会再次展示这段 secret。请立即复制并保存到调用方配置中，然后关闭提示。
              </p>
            </div>
          </div>
          <div className="rounded-xl bg-surface-hover px-4 py-3">
            <p className="mb-1 text-[11px] uppercase tracking-[0.16em] text-ink-tertiary">Client Secret</p>
            <code className="block break-all text-sm text-ink">{secretNotice.secret}</code>
          </div>
          <div className="mt-3 flex items-center justify-between gap-3">
            <p className="text-xs text-ink-tertiary">Client ID: {secretNotice.clientId}</p>
            <button
              onClick={() => setSecretNotice(null)}
              className="rounded-lg border border-line px-3 py-1.5 text-xs font-medium text-ink-secondary transition-colors hover:bg-surface-hover"
            >
              已保存，关闭提示
            </button>
          </div>
        </div>
      )}

      {error && (
        <div className="mb-5 rounded-xl bg-warn-soft px-4 py-3 text-sm text-warn">
          {error}
        </div>
      )}

      <div className="overflow-hidden rounded-xl border border-line bg-surface-solid">
        {loading ? (
          <div className="space-y-4 p-6">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="flex animate-pulse items-center gap-4">
                <div className="h-12 w-48 rounded bg-surface-hover" />
                <div className="h-8 flex-1 rounded bg-surface-hover" />
                <div className="h-8 w-24 rounded bg-surface-hover" />
              </div>
            ))}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-line">
                  <th className="px-6 py-3.5 text-left text-xs font-semibold uppercase tracking-wider text-ink-tertiary">应用名称</th>
                  <th className="px-6 py-3.5 text-left text-xs font-semibold uppercase tracking-wider text-ink-tertiary">Client ID</th>
                  <th className="px-6 py-3.5 text-left text-xs font-semibold uppercase tracking-wider text-ink-tertiary">Scopes</th>
                  <th className="px-6 py-3.5 text-left text-xs font-semibold uppercase tracking-wider text-ink-tertiary">状态</th>
                  <th className="px-6 py-3.5 text-left text-xs font-semibold uppercase tracking-wider text-ink-tertiary">自动成员</th>
                  <th className="px-6 py-3.5 text-left text-xs font-semibold uppercase tracking-wider text-ink-tertiary">密钥轮换</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {clients.map((client) => (
                  <tr key={client.client_id} className="transition-colors hover:bg-surface-hover">
                    <td className="px-6 py-4">
                      <p className="text-sm font-medium text-ink">{client.name}</p>
                      <p className="mt-0.5 text-xs text-ink-tertiary">{client.redirect_uris.length} 个回调地址</p>
                    </td>
                    <td className="px-6 py-4">
                      <code className="rounded bg-surface-hover px-2 py-1 font-mono text-xs text-ink-secondary">{client.client_id}</code>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-wrap gap-1">
                        {client.scopes.map(scope => (
                          <span key={scope} className="rounded bg-surface-hover px-1.5 py-0.5 text-[10px] font-medium text-ink-secondary">
                            {scope}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <StatusBadge status={client.status} />
                        <select
                          value={client.status}
                          disabled={pendingStatusClientId === client.client_id}
                          onChange={(event) => {
                            const nextStatus = event.target.value as ClientStatus;
                            if (nextStatus !== client.status) {
                              void handleStatusChange(client.client_id, nextStatus);
                            }
                          }}
                          className="rounded-lg border border-line bg-surface-solid px-3 py-1.5 text-xs text-ink outline-none transition-colors focus:border-line-strong disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          {STATUS_OPTIONS.map(status => (
                            <option key={status} value={status}>{status}</option>
                          ))}
                        </select>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      {client.auto_provision_members ? (
                        <span className="inline-flex items-center gap-1 text-xs text-ok">
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><path d="m9 12 2 2 4-4" /></svg>
                          已启用
                        </span>
                      ) : (
                        <span className="text-xs text-ink-tertiary">-</span>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-ink-secondary">{client.last_rotated}</span>
                        <button
                          onClick={() => void handleRotateSecret(client.client_id)}
                          disabled={pendingRotateClientId === client.client_id}
                          className="rounded p-1 transition-colors hover:bg-surface-hover disabled:cursor-not-allowed disabled:opacity-60"
                          title="轮换密钥"
                        >
                          <IconRefreshCw size={14} className="text-ink-tertiary" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {!clients.length && (
                  <tr>
                    <td colSpan={6} className="px-6 py-12 text-center text-sm text-ink-tertiary">
                      暂无 OAuth Client，先注册一个用于 OIDC 集成。
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <Drawer isOpen={drawerOpen} onClose={() => { setDrawerOpen(false); resetCreateForm(); }} title="注册 OAuth Client" width="560px">
        <form onSubmit={handleCreateClient} className="space-y-5">
          <div className="grid gap-5 md:grid-cols-2">
            <label className="block">
              <span className="mb-2 block text-sm font-medium text-ink">Tenant ID</span>
              <input
                value={form.tenant_id}
                onChange={event => updateForm('tenant_id', event.target.value)}
                className="w-full rounded-xl border border-line bg-surface-solid px-3 py-2.5 text-sm text-ink outline-none transition-colors focus:border-line-strong"
                placeholder="例如 1"
              />
            </label>
            <label className="block">
              <span className="mb-2 block text-sm font-medium text-ink">Client 名称</span>
              <input
                value={form.name}
                onChange={event => updateForm('name', event.target.value)}
                className="w-full rounded-xl border border-line bg-surface-solid px-3 py-2.5 text-sm text-ink outline-none transition-colors focus:border-line-strong"
                placeholder="Admin Web"
              />
            </label>
          </div>

          <div className="grid gap-5 md:grid-cols-2">
            <label className="block">
              <span className="mb-2 block text-sm font-medium text-ink">Client ID</span>
              <input
                value={form.client_id}
                onChange={event => updateForm('client_id', event.target.value)}
                className="w-full rounded-xl border border-line bg-surface-solid px-3 py-2.5 text-sm text-ink outline-none transition-colors focus:border-line-strong"
                placeholder="admin-web"
              />
            </label>
            <label className="block">
              <span className="mb-2 block text-sm font-medium text-ink">认证方式</span>
              <select
                value={form.token_endpoint_auth_method}
                onChange={event => updateForm('token_endpoint_auth_method', event.target.value as CreateFormState['token_endpoint_auth_method'])}
                className="w-full rounded-xl border border-line bg-surface-solid px-3 py-2.5 text-sm text-ink outline-none transition-colors focus:border-line-strong"
              >
                <option value="client_secret_post">client_secret_post</option>
                <option value="client_secret_basic">client_secret_basic</option>
              </select>
            </label>
          </div>

          <label className="block">
            <span className="mb-2 block text-sm font-medium text-ink">Client Secret</span>
            <input
              value={form.client_secret}
              onChange={event => updateForm('client_secret', event.target.value)}
              className="w-full rounded-xl border border-line bg-surface-solid px-3 py-2.5 text-sm text-ink outline-none transition-colors focus:border-line-strong"
              placeholder="创建后请立即保存"
            />
          </label>

          <label className="block">
            <span className="mb-2 block text-sm font-medium text-ink">Redirect URIs</span>
            <textarea
              value={form.redirect_uris}
              onChange={event => updateForm('redirect_uris', event.target.value)}
              rows={4}
              className="w-full rounded-xl border border-line bg-surface-solid px-3 py-2.5 text-sm text-ink outline-none transition-colors focus:border-line-strong"
              placeholder={'每行一个回调地址\nhttps://admin.example.com/callback'}
            />
          </label>

          <label className="block">
            <span className="mb-2 block text-sm font-medium text-ink">Scopes</span>
            <textarea
              value={form.scopes}
              onChange={event => updateForm('scopes', event.target.value)}
              rows={4}
              className="w-full rounded-xl border border-line bg-surface-solid px-3 py-2.5 text-sm text-ink outline-none transition-colors focus:border-line-strong"
              placeholder={'每行一个 scope\nopenid\nprofile\nemail'}
            />
          </label>

          <label className="flex items-center gap-3 rounded-xl border border-line bg-surface-hover px-4 py-3">
            <input
              type="checkbox"
              checked={form.auto_provision_members}
              onChange={event => updateForm('auto_provision_members', event.target.checked)}
              style={{ width: '18px', height: '18px', accentColor: 'var(--ink)' }}
            />
            <span className="text-sm text-ink">启用自动成员创建</span>
          </label>

          {formError && (
            <div className="rounded-xl bg-warn-soft px-4 py-3 text-sm text-warn">
              {formError}
            </div>
          )}

          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={() => {
                setDrawerOpen(false);
                resetCreateForm();
              }}
              className="rounded-lg border border-line px-4 py-2 text-sm font-medium text-ink-secondary transition-colors hover:bg-surface-hover"
            >
              取消
            </button>
            <button
              type="submit"
              disabled={creating}
              className="rounded-lg bg-ink px-4 py-2 text-sm font-medium text-ink-inverse transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {creating ? '创建中...' : '创建 Client'}
            </button>
          </div>
        </form>
      </Drawer>

      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
}
