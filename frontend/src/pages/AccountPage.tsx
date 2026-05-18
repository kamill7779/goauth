import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  getAccountMe,
  getAccountSessions,
  getAccountLoginMethods,
  getAccountAuthorizedApps,
  getAccount2FAStatus,
} from '../api/account';
import BrandMark from '../components/BrandMark';
import ThemeToggle from '../components/admin/ThemeToggle';
import AccountModal from '../components/account/AccountModal';
import AccountToast from '../components/account/AccountToast';
import OverviewTab from '../components/account/tabs/OverviewTab';
import ProfileTab from '../components/account/tabs/ProfileTab';
import LoginMethodsTab from '../components/account/tabs/LoginMethodsTab';
import SecurityTab from '../components/account/tabs/SecurityTab';
import AuthorizedAppsTab from '../components/account/tabs/AuthorizedAppsTab';
import {
  IconHome,
  IconUser,
  IconKey,
  IconShield,
  IconApps,
  IconLogOut,
  IconBell,
  IconMenu,
  IconX,
} from '../components/admin/Icons';
import { usePublicBrand } from '../hooks/usePublicBrand';
import type { AccountMe, AccountSession } from '../types/account';
import type { ToastItem } from '../components/account/AccountToast';

function clearStoredTokens() {
  window.localStorage.removeItem('access_token');
  window.localStorage.removeItem('refresh_token');
}

const TABS = [
  { id: 'overview' as const, label: '概览', icon: IconHome },
  { id: 'profile' as const, label: '个人资料', icon: IconUser },
  { id: 'login' as const, label: '登录方式', icon: IconKey },
  { id: 'security' as const, label: '安全中心', icon: IconShield },
  { id: 'apps' as const, label: '已授权应用', icon: IconApps },
];

type TabId = (typeof TABS)[number]['id'];

export default function AccountPage() {
  const navigate = useNavigate();
  const brand = usePublicBrand();
  const [account, setAccount] = useState<AccountMe | null>(null);
  const [sessions, setSessions] = useState<AccountSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [tab, setTab] = useState<TabId>('overview');
  const [toast, setToast] = useState<ToastItem | null>(null);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [loginMethods, setLoginMethods] = useState<Awaited<ReturnType<typeof getAccountLoginMethods>>['methods']>([]);
  const [authorizedApps, setAuthorizedApps] = useState<Awaited<ReturnType<typeof getAccountAuthorizedApps>>['apps']>([]);
  const [twoFAEnabled, setTwoFAEnabled] = useState(false);
  const [securityScore, setSecurityScore] = useState(72);

  const leaveToLogin = useCallback(() => {
    clearStoredTokens();
    navigate('/login', { replace: true });
  }, [navigate]);

  const showToast = useCallback((message: string, type: ToastItem['type'] = 'success') => {
    setToast({ id: `${Date.now()}`, message, type });
  }, []);

  const loadAccount = useCallback(async () => {
    const token = window.localStorage.getItem('access_token');
    if (!token) {
      leaveToLogin();
      return;
    }
    setLoading(true);
    setError('');
    try {
      const [me, sess, methods, apps, fa] = await Promise.all([
        getAccountMe(),
        getAccountSessions(),
        getAccountLoginMethods(),
        getAccountAuthorizedApps(),
        getAccount2FAStatus(),
      ]);
      setAccount(me);
      setSessions(sess.sessions);
      setLoginMethods(methods.methods);
      setAuthorizedApps(apps.apps);
      setTwoFAEnabled(fa.enabled);
      // compute security score
      let score = 40;
      if (me.user.email_verified) score += 15;
      if (fa.enabled) score += 20;
      const boundCount = methods.methods.filter((m) => m.bound).length;
      if (boundCount >= 2) score += 15;
      if (boundCount >= 3) score += 10;
      setSecurityScore(Math.min(100, score));
    } catch (err) {
      setError(err instanceof Error ? err.message : '账号信息加载失败');
    } finally {
      setLoading(false);
    }
  }, [leaveToLogin]);

  useEffect(() => {
    loadAccount();
  }, [loadAccount]);

  const user = account?.user;
  const displayName = user?.display_name || user?.nickname || user?.username || user?.email || 'GoAuth User';

  const tabContent = useMemo(() => {
    if (loading) {
      return (
        <div className="flex min-h-[360px] items-center justify-center">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-line-strong border-t-ink" />
        </div>
      );
    }
    if (!user) {
      return (
        <div className="flex min-h-[360px] flex-col items-center justify-center gap-3 text-center">
          <p className="text-sm text-ink-tertiary">无法加载账号信息</p>
          <button onClick={loadAccount} className="rounded-xl border border-line bg-surface-muted px-4 py-2 text-sm font-medium hover:bg-surface-hover">重试</button>
        </div>
      );
    }
    const shared = {
      user,
      account,
      sessions,
      loginMethods,
      setLoginMethods,
      authorizedApps,
      setAuthorizedApps,
      twoFAEnabled,
      setTwoFAEnabled,
      securityScore,
      setSecurityScore,
      showToast,
      refresh: loadAccount,
      setTab,
    };
    switch (tab) {
      case 'overview':
        return <OverviewTab {...shared} />;
      case 'profile':
        return <ProfileTab {...shared} />;
      case 'login':
        return <LoginMethodsTab {...shared} />;
      case 'security':
        return <SecurityTab {...shared} />;
      case 'apps':
        return <AuthorizedAppsTab {...shared} />;
      default:
        return null;
    }
  }, [tab, loading, user, account, sessions, loginMethods, authorizedApps, twoFAEnabled, securityScore, loadAccount, showToast]);

  return (
    <div className="min-h-screen bg-canvas text-ink">
      {/* Header */}
      <header className="sticky top-0 z-30 border-b border-line bg-canvas/80 backdrop-blur-xl">
        <div className="mx-auto flex w-full max-w-6xl items-center justify-between px-5 py-3.5">
          <div className="flex items-center gap-3">
            <BrandMark brand={brand} size="sm" orientation="horizontal" align="left" showTagline={false} />
            <span className="hidden text-xs text-ink-tertiary md:inline">· 账户中心</span>
          </div>
          <div className="hidden text-sm italic text-ink-tertiary md:block">
            「这是你在所有接入应用中的统一身份」
          </div>
          <div className="flex items-center gap-2">
            <button className="inline-flex h-9 w-9 items-center justify-center rounded-lg text-ink-tertiary transition-colors hover:bg-surface-hover hover:text-ink">
              <IconBell size={18} />
            </button>
            <ThemeToggle variant="inline" />
            <button
              onClick={() => {
                clearStoredTokens();
                navigate('/login', { replace: true });
              }}
              className="hidden items-center gap-1.5 rounded-lg border border-line bg-surface-solid px-3 py-2 text-sm font-medium text-ink-secondary transition-colors hover:bg-surface-hover hover:text-ink md:inline-flex"
            >
              <IconLogOut size={14} />
              退出
            </button>
            <button
              className="inline-flex h-9 w-9 items-center justify-center rounded-lg text-ink-tertiary transition-colors hover:bg-surface-hover hover:text-ink md:hidden"
              onClick={() => setMobileNavOpen(true)}
            >
              <IconMenu size={20} />
            </button>
          </div>
        </div>
      </header>

      {/* Hero identity */}
      <section className="mx-auto w-full max-w-6xl px-5 pt-8">
        <div className="relative overflow-hidden rounded-[24px] border border-line bg-surface-solid p-7 shadow-soft-md">
          <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-brand-soft/40 via-transparent to-transparent" />
          <div className="relative flex flex-wrap items-center gap-6">
            <div className="flex h-[88px] w-[88px] shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-[#C99B6E] to-[#9A6E47] text-[28px] font-medium text-white shadow-lg"
              style={{ fontFamily: '"Newsreader", serif', fontStyle: 'italic' }}
            >
              {user?.avatar_url ? (
                <img src={user.avatar_url} alt="" className="h-full w-full rounded-full object-cover" />
              ) : (
                displayName.slice(0, 1)
              )}
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-3">
                <h1 className="text-2xl font-semibold tracking-tight text-ink md:text-3xl">{displayName}</h1>
                {user?.email_verified && (
                  <span className="inline-flex items-center gap-1 rounded-full bg-ok-soft px-2.5 py-1 text-xs font-medium text-ok">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>
                    已验证
                  </span>
                )}
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-ink-secondary">
                <span className="font-mono">@{user?.username}</span>
                <span className="hidden h-1 w-1 rounded-full bg-ink-muted md:inline" />
                <span className="flex items-center gap-1.5">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
                  {user?.email}
                </span>
              </div>
              <p className="mt-3 max-w-xl text-sm leading-relaxed text-ink-secondary italic">
                这是你在所有接入应用中的统一身份 — 头像、名字、邮箱、安全设置 在这里管一次，处处生效。
              </p>
            </div>
            <div className="hidden flex-col items-end gap-1 md:flex">
              <div className="text-xs text-ink-tertiary">账号创建于</div>
              <div className="text-lg font-medium">{user?.created_at?.slice(0, 10) || '-'}</div>
            </div>
          </div>
        </div>
      </section>

      {/* Tabs */}
      <nav className="mx-auto w-full max-w-6xl px-5 pt-6">
        <div className="inline-flex gap-1 rounded-2xl border border-line bg-surface p-1.5 shadow-soft-sm">
          {TABS.map((t) => {
            const Icon = t.icon;
            const active = tab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`inline-flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-medium transition-all ${
                  active
                    ? 'bg-surface-solid text-ink shadow-soft-sm'
                    : 'text-ink-secondary hover:text-ink hover:bg-surface-hover'
                }`}
              >
                <Icon size={16} />
                <span className="hidden sm:inline">{t.label}</span>
              </button>
            );
          })}
        </div>
      </nav>

      {/* Content */}
      <main className="mx-auto w-full max-w-6xl px-5 pb-20 pt-5">
        {error && (
          <div className="mb-6 rounded-2xl border border-danger bg-danger-soft px-5 py-3.5 text-sm text-danger">
            {error}
          </div>
        )}
        <div key={tab + (loading ? '-loading' : '')} className="animate-fade-in-up">
          {tabContent}
        </div>
      </main>

      {/* Mobile nav drawer */}
      {mobileNavOpen && (
        <AccountModal open={mobileNavOpen} onClose={() => setMobileNavOpen(false)} maxWidth={320}>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-medium">菜单</span>
              <button onClick={() => setMobileNavOpen(false)} className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-ink-tertiary hover:bg-surface-hover">
                <IconX size={18} />
              </button>
            </div>
            <div className="h-px bg-line" />
            <button
              onClick={() => {
                clearStoredTokens();
                navigate('/login', { replace: true });
              }}
              className="flex w-full items-center gap-2 rounded-xl px-3 py-2.5 text-left text-sm font-medium text-ink-secondary transition-colors hover:bg-surface-hover hover:text-ink"
            >
              <IconLogOut size={16} />
              退出登录
            </button>
          </div>
        </AccountModal>
      )}

      {/* Toast */}
      <AccountToast toast={toast} onDismiss={() => setToast(null)} />
    </div>
  );
}
