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
      <div className="min-h-screen bg-[#FAFAF8] flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-gray-300 border-t-gray-900 rounded-full animate-spin" />
      </div>
    );
  }

  if (!allowed && !denied) {
    return <Navigate to="/login" replace />;
  }

  if (denied) {
    return (
      <div className="min-h-screen bg-[#FAFAF8] flex items-center justify-center px-6">
        <div className="w-full max-w-md rounded-2xl border border-gray-200 bg-white p-8 text-center shadow-sm">
          <div className="mx-auto mb-5 flex h-11 w-11 items-center justify-center rounded-xl bg-gray-900 text-sm font-semibold text-white">
            G
          </div>
          <h1 className="mb-2 text-xl font-semibold text-gray-900">无权访问 Admin Console</h1>
          <p className="mb-6 text-sm leading-6 text-gray-500">
            当前账号不是 GoAuth 系统管理员。请使用拥有 root 或 system-admin 角色的账号登录。
          </p>
          <button
            onClick={() => {
              localStorage.removeItem('access_token');
              localStorage.removeItem('refresh_token');
              window.location.href = '/login';
            }}
            className="rounded-lg bg-gray-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-gray-800"
          >
            重新登录
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#FAFAF8]">
      <Header />
      <Sidebar />
      <main className="ml-[250px] mt-[72px] p-8 min-h-[calc(100vh-72px)]">
        {children}
      </main>
    </div>
  );
}
