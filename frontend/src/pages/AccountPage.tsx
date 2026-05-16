import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getAccountMe, getAccountSessions, logoutAllAccountSessions, revokeAccountSession } from '../api/account';
import BrandMark from '../components/BrandMark';
import ThemeToggle from '../components/admin/ThemeToggle';
import {
  IconActivity,
  IconCheckCircle,
  IconLogOut,
  IconMonitor,
  IconRefreshCw,
  IconShield,
} from '../components/admin/Icons';
import { usePublicBrand } from '../hooks/usePublicBrand';
import type { AccountMe, AccountSession } from '../types/account';

function formatDate(value: string) {
  if (!value) {
    return '-';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString('zh-CN', { hour12: false });
}

function statusLabel(status: string) {
  switch (status) {
    case 'active':
      return '活跃';
    case 'revoked':
      return '已下线';
    case 'expired':
      return '已过期';
    default:
      return '未活跃';
  }
}

function clearStoredTokens() {
  window.localStorage.removeItem('access_token');
  window.localStorage.removeItem('refresh_token');
}

export default function AccountPage() {
  const navigate = useNavigate();
  const brand = usePublicBrand();
  const [account, setAccount] = useState<AccountMe | null>(null);
  const [sessions, setSessions] = useState<AccountSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busySessionId, setBusySessionId] = useState<string | null>(null);
  const [loggingOutAll, setLoggingOutAll] = useState(false);

  const leaveToLogin = useCallback(() => {
    clearStoredTokens();
    navigate('/login', { replace: true });
  }, [navigate]);

  const loadAccount = useCallback(async () => {
    const token = window.localStorage.getItem('access_token');
    if (!token) {
      leaveToLogin();
      return;
    }

    setLoading(true);
    setError('');
    try {
      const [nextAccount, nextSessions] = await Promise.all([
        getAccountMe(),
        getAccountSessions(),
      ]);
      setAccount(nextAccount);
      setSessions(nextSessions.sessions);
    } catch (err) {
      setError(err instanceof Error ? err.message : '账号信息加载失败');
    } finally {
      setLoading(false);
    }
  }, [leaveToLogin]);

  useEffect(() => {
    loadAccount();
  }, [loadAccount]);

  const handleRevokeSession = async (session: AccountSession) => {
    const confirmed = window.confirm(session.current ? '确认退出当前会话？' : '确认下线这个会话？');
    if (!confirmed) {
      return;
    }

    setBusySessionId(session.id);
    setError('');
    try {
      await revokeAccountSession(session.id);
      if (session.current) {
        leaveToLogin();
        return;
      }
      await loadAccount();
    } catch (err) {
      setError(err instanceof Error ? err.message : '会话下线失败');
    } finally {
      setBusySessionId(null);
    }
  };

  const handleLogoutAll = async () => {
    const confirmed = window.confirm('确认退出当前账号的所有会话？');
    if (!confirmed) {
      return;
    }

    setLoggingOutAll(true);
    setError('');
    try {
      await logoutAllAccountSessions();
      leaveToLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : '退出所有会话失败');
    } finally {
      setLoggingOutAll(false);
    }
  };

  const user = account?.user;
  const displayName = user?.nickname || user?.display_name || user?.username || user?.email || 'GoAuth User';
  const activeCount = sessions.filter(session => session.status === 'active').length;

  return (
    <div className="min-h-screen bg-canvas-subtle text-ink">
      <header className="border-b border-line bg-surface-solid">
        <div className="mx-auto flex w-full max-w-6xl items-center justify-between px-5 py-4">
          <BrandMark brand={brand} size="sm" orientation="horizontal" align="left" showTagline={false} />
          <div className="flex items-center gap-2">
            {account?.is_admin && (
              <button
                onClick={() => navigate('/admin')}
                className="inline-flex items-center gap-2 rounded-lg border border-line bg-surface-solid px-3 py-2 text-sm font-medium text-ink-secondary transition-colors hover:bg-surface-hover hover:text-ink"
              >
                <IconShield size={16} />
                Admin Console
              </button>
            )}
            <ThemeToggle variant="inline" />
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-6xl px-5 py-8 md:py-10">
        {loading ? (
          <div className="flex min-h-[360px] items-center justify-center">
            <div className="h-7 w-7 animate-spin rounded-full border-2 border-line-strong border-t-ink" />
          </div>
        ) : (
          <div className="space-y-6">
            <section className="flex flex-col gap-5 border-b border-line pb-6 md:flex-row md:items-center md:justify-between">
              <div className="flex min-w-0 items-center gap-4">
                <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-brand-soft text-xl font-semibold text-brand">
                  {displayName.slice(0, 1).toUpperCase()}
                </div>
                <div className="min-w-0">
                  <h1 className="truncate text-2xl font-semibold text-ink">{displayName}</h1>
                  <p className="mt-1 truncate text-sm text-ink-secondary">{user?.email}</p>
                  <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
                    <span className="inline-flex items-center gap-1 rounded-full bg-ok-soft px-2.5 py-1 font-medium text-ok">
                      <IconCheckCircle size={14} />
                      {user?.email_verified ? '邮箱已验证' : '邮箱待验证'}
                    </span>
                    {account?.is_admin && (
                      <span className="inline-flex items-center gap-1 rounded-full bg-info-soft px-2.5 py-1 font-medium text-info">
                        <IconShield size={14} />
                        系统管理员
                      </span>
                    )}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 sm:min-w-[300px]">
                <div className="rounded-xl border border-line bg-surface-muted p-4">
                  <p className="text-xs text-ink-tertiary">活跃会话</p>
                  <p className="mt-1 text-2xl font-semibold text-ink">{activeCount}</p>
                </div>
                <div className="rounded-xl border border-line bg-surface-muted p-4">
                  <p className="text-xs text-ink-tertiary">当前租户</p>
                  <p className="mt-1 truncate text-2xl font-semibold text-ink">{account?.session.tenant_id || '-'}</p>
                </div>
              </div>
            </section>

            {error && (
              <div className="rounded-xl border border-danger bg-danger-soft px-4 py-3 text-sm text-danger">
                {error}
              </div>
            )}

            <section>
              <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h2 className="text-lg font-semibold text-ink">我的会话</h2>
                  <p className="mt-1 text-sm text-ink-tertiary">查看当前账号最近 100 个登录会话，并下线不再使用的设备。</p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    onClick={loadAccount}
                    disabled={loading}
                    className="inline-flex items-center gap-2 rounded-lg border border-line bg-surface-solid px-3 py-2 text-sm font-medium text-ink-secondary transition-colors hover:bg-surface-hover disabled:opacity-50"
                  >
                    <IconRefreshCw size={16} className={loading ? 'animate-spin' : ''} />
                    刷新
                  </button>
                  <button
                    onClick={handleLogoutAll}
                    disabled={loggingOutAll}
                    className="inline-flex items-center gap-2 rounded-lg bg-danger px-3 py-2 text-sm font-medium text-ink-inverse transition-colors hover:bg-danger-strong disabled:opacity-50"
                  >
                    <IconLogOut size={16} />
                    退出所有会话
                  </button>
                </div>
              </div>

              {sessions.length === 0 ? (
                <div className="rounded-[20px] border border-line bg-surface-solid px-6 py-14 text-center">
                  <IconMonitor size={24} className="mx-auto mb-3 text-ink-tertiary" />
                  <p className="text-sm font-medium text-ink">暂无会话记录</p>
                </div>
              ) : (
                <div className="grid gap-3">
                  {sessions.map(session => (
                    <article
                      key={session.id}
                      className="grid gap-4 rounded-[16px] border border-line bg-surface-solid p-4 shadow-soft-sm md:grid-cols-[1fr_auto] md:items-center"
                    >
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="truncate text-sm font-semibold text-ink">{session.client || 'GoAuth'}</p>
                          {session.current && (
                            <span className="rounded-full bg-brand-soft px-2 py-0.5 text-xs font-medium text-brand">当前会话</span>
                          )}
                          <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                            session.status === 'active'
                              ? 'bg-ok-soft text-ok'
                              : session.status === 'revoked'
                                ? 'bg-danger-soft text-danger'
                                : 'bg-surface-hover text-ink-tertiary'
                          }`}>
                            {statusLabel(session.status)}
                          </span>
                        </div>
                        <div className="mt-3 grid gap-2 text-xs text-ink-tertiary sm:grid-cols-2 lg:grid-cols-4">
                          <span className="truncate">会话：{session.id}</span>
                          <span className="truncate">IP：{session.ip || '-'}</span>
                          <span className="truncate">创建：{formatDate(session.created_at)}</span>
                          <span className="truncate">过期：{formatDate(session.expires_at)}</span>
                        </div>
                        {session.user_agent && (
                          <p className="mt-2 truncate text-xs text-ink-muted">{session.user_agent}</p>
                        )}
                      </div>
                      <div className="flex items-center justify-end gap-2">
                        <IconActivity size={16} className="hidden text-ink-tertiary md:block" />
                        <button
                          onClick={() => handleRevokeSession(session)}
                          disabled={session.status !== 'active' || busySessionId === session.id}
                          className="inline-flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-sm font-medium text-ink-secondary transition-colors hover:bg-danger-soft hover:text-danger disabled:cursor-not-allowed disabled:opacity-40"
                        >
                          <IconLogOut size={16} />
                          {session.current ? '退出当前' : '下线'}
                        </button>
                      </div>
                    </article>
                  ))}
                </div>
              )}
            </section>
          </div>
        )}
      </main>
    </div>
  );
}
