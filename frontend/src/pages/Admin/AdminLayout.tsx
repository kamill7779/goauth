import { useState, useEffect } from 'react';
import { Navigate } from 'react-router-dom';
import Header from '../../components/admin/Header';
import Sidebar from '../../components/admin/Sidebar';
import { checkAdminAccess } from '../../api/admin';

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const [checking, setChecking] = useState(true);
  const [allowed, setAllowed] = useState(false);
  const [denied, setDenied] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) {
      setChecking(false);
      return;
    }

    checkAdminAccess()
      .then(() => setAllowed(true))
      .catch(() => setDenied(true))
      .finally(() => setChecking(false));
  }, []);

  if (checking) {
    return (
      <div className="min-h-screen bg-canvas-subtle flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-line-strong border-t-ink rounded-full animate-spin" />
      </div>
    );
  }

  if (!allowed && !denied) {
    return <Navigate to="/login" replace />;
  }

  if (denied) {
    return (
      <div className="min-h-screen bg-canvas-subtle flex items-center justify-center px-6">
        <div className="w-full max-w-md rounded-2xl border border-line bg-surface-solid p-8 text-center shadow-soft-sm">
          <div className="mx-auto mb-5 flex h-11 w-11 items-center justify-center rounded-xl bg-ink text-sm font-semibold text-ink-inverse">
            G
          </div>
          <h1 className="mb-2 text-xl font-semibold text-ink">无权访问 Admin Console</h1>
          <p className="mb-6 text-sm leading-6 text-ink-secondary">
            当前账号不是 GoAuth 系统管理员。请使用拥有 root 或 system-admin 角色的账号登录。
          </p>
          <button
            onClick={() => {
              localStorage.removeItem('access_token');
              localStorage.removeItem('refresh_token');
              window.location.href = '/login';
            }}
            className="rounded-lg bg-ink px-4 py-2 text-sm font-medium text-ink-inverse transition-colors hover:opacity-90"
          >
            重新登录
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-canvas-subtle">
      <Header />
      <Sidebar />
      <main className="ml-[250px] mt-[72px] p-8 min-h-[calc(100vh-72px)]">
        {children}
      </main>
    </div>
  );
}
