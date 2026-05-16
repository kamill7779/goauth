import { useState, useEffect } from 'react';
import { Navigate } from 'react-router-dom';
import Header from '../../components/admin/Header';
import Sidebar from '../../components/admin/Sidebar';
import { checkAdminAccess, classifyAdminAccessError } from '../../api/admin';
import BrandMark from '../../components/BrandMark';
import { usePublicBrand } from '../../hooks/usePublicBrand';

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const [accessState, setAccessState] = useState<'checking' | 'allowed' | 'unauthenticated' | 'forbidden' | 'unavailable'>('checking');
  const brand = usePublicBrand();

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) {
      setAccessState('unauthenticated');
      return;
    }

    checkAdminAccess()
      .then(() => setAccessState('allowed'))
      .catch((error) => setAccessState(classifyAdminAccessError(error)));
  }, []);

  if (accessState === 'checking') {
    return (
      <div className="min-h-screen bg-canvas-subtle flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-line-strong border-t-ink rounded-full animate-spin" />
      </div>
    );
  }

  if (accessState === 'unauthenticated') {
    return <Navigate to="/login" replace />;
  }

  if (accessState === 'forbidden') {
    return (
      <div className="min-h-screen bg-canvas-subtle flex items-center justify-center px-6">
        <div className="w-full max-w-md rounded-[24px] border border-line bg-surface-solid p-8 text-center shadow-soft-sm">
          <div className="mb-5 flex justify-center">
            <BrandMark brand={brand} size="md" orientation="stacked" align="center" showTagline={false} />
          </div>
          <h1 className="mb-2 text-xl font-semibold text-ink">无权访问 Admin Console</h1>
          <p className="mb-6 text-sm leading-6 text-ink-secondary">
            当前账号不是 {brand.name} 系统管理员。请使用拥有 root 或 system-admin 角色的账号登录。
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

  if (accessState === 'unavailable') {
    return (
      <div className="min-h-screen bg-canvas-subtle flex items-center justify-center px-6">
        <div className="w-full max-w-md rounded-[24px] border border-line bg-surface-solid p-8 text-center shadow-soft-sm">
          <div className="mx-auto mb-5 flex h-11 w-11 items-center justify-center rounded-xl bg-surface-hover text-sm font-semibold text-ink">
            !
          </div>
          <h1 className="mb-2 text-xl font-semibold text-ink">Admin Console 暂时不可用</h1>
          <p className="mb-6 text-sm leading-6 text-ink-secondary">
            无法完成管理员权限校验。请检查后端服务或网络连接后重试。
          </p>
          <div className="flex items-center justify-center gap-3">
            <button
              onClick={() => window.location.reload()}
              className="rounded-lg bg-ink px-4 py-2 text-sm font-medium text-ink-inverse transition-colors hover:opacity-90"
            >
              重新检查
            </button>
            <button
              onClick={() => {
                localStorage.removeItem('access_token');
                localStorage.removeItem('refresh_token');
                window.location.href = '/login';
              }}
              className="rounded-lg border border-line px-4 py-2 text-sm font-medium text-ink-secondary transition-colors hover:bg-surface-hover"
            >
              返回登录
            </button>
          </div>
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
