import { useState, useRef, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { IconSearch, IconBell, IconLogOut } from './Icons';
import { logout } from '../../api/admin';
import { useAuth } from '../../hooks/useAuth';

const navItems = [
  { id: 'overview', label: '总览', paths: ['/admin', '/admin/dashboard'] },
  { id: 'identity', label: '身份', paths: ['/admin/users', '/admin/roles'] },
  { id: 'tenants', label: '租户', paths: ['/admin/tenants'] },
  { id: 'applications', label: '应用', paths: ['/admin/oauth', '/admin/sessions', '/admin/security'] },
  { id: 'audit', label: '审计', paths: ['/admin/audit'] },
  { id: 'system', label: '系统', paths: ['/admin/settings'] },
];

export default function Header() {
  const navigate = useNavigate();
  const location = useLocation();
  const { user } = useAuth();
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const notifRef = useRef<HTMLDivElement>(null);
  const profileRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) setNotificationsOpen(false);
      if (profileRef.current && !profileRef.current.contains(e.target as Node)) setProfileOpen(false);
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const currentNav = navItems.find(n => n.paths.includes(location.pathname)) || navItems[0];

  const handleNavClick = (paths: string[]) => {
    navigate(paths[0]);
  };

  const handleLogout = async () => {
    try { await logout(); } catch { /* ignore */ }
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    window.location.href = '/login';
  };

  const displayEmail = user?.email || '账号加载中';
  const avatarLabel = displayEmail.charAt(0).toUpperCase();

  return (
    <header className="fixed top-0 left-0 right-0 h-[72px] bg-white/80 backdrop-blur-xl border-b border-[#E8E8E6] z-50 flex items-center px-6">
      <div className="flex items-center gap-3 w-[250px] flex-shrink-0">
        <div className="w-8 h-8 bg-gray-900 rounded-lg flex items-center justify-center">
          <span className="text-white text-xs font-bold">G</span>
        </div>
        <div className="flex flex-col">
          <span className="text-sm font-semibold text-gray-900 leading-tight">GoAuth</span>
          <span className="text-[10px] text-gray-400 leading-tight">by KMSoft</span>
        </div>
      </div>

      <nav className="flex-1 flex justify-center">
        <div className="inline-flex items-center gap-1 bg-gray-100 rounded-full p-1">
          {navItems.map(item => (
            <button
              key={item.id}
              onClick={() => handleNavClick(item.paths)}
              className={`px-4 py-1.5 text-sm font-medium rounded-full transition-all duration-200 ${
                currentNav.id === item.id
                  ? 'bg-gray-900 text-white shadow-sm'
                  : 'text-gray-500 hover:text-gray-700 hover:bg-gray-200/50'
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>
      </nav>

      <div className="flex items-center gap-2">
        <button
          onClick={() => navigate('/admin/users')}
          className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-400 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors"
        >
          <IconSearch size={14} />
          <span className="text-xs">搜索</span>
          <kbd className="px-1 py-0.5 text-[10px] font-mono bg-white text-gray-400 rounded border border-gray-200">⌘K</kbd>
        </button>

        <div className="relative" ref={notifRef}>
          <button
            onClick={() => setNotificationsOpen(!notificationsOpen)}
            className="relative p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <IconBell size={18} className="text-gray-500" />
            <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full" />
          </button>
          {notificationsOpen && (
            <div className="absolute right-0 top-full mt-2 w-80 bg-white rounded-xl border border-gray-200 shadow-xl overflow-hidden">
              <div className="px-4 py-3 border-b border-gray-200 flex items-center justify-between">
                <span className="text-sm font-medium">通知</span>
                <span className="text-xs text-gray-400">3 条未读</span>
              </div>
              <div className="max-h-64 overflow-y-auto">
                {[
                  { title: '异常登录检测', desc: '用户 lisi@example.com 多次登录失败', time: '2 分钟前', type: 'warning' },
                  { title: 'OAuth Client 密钥即将过期', desc: 'acme-web-app 的密钥将在 7 天后过期', time: '1 小时前', type: 'info' },
                  { title: '新用户注册', desc: 'zhaoliu@dev.com 等待审核', time: '3 小时前', type: 'success' },
                ].map((n, i) => (
                  <div key={i} className="px-4 py-3 hover:bg-gray-50 border-b border-gray-100 last:border-0 cursor-pointer transition-colors">
                    <div className="flex items-start gap-2">
                      <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${
                        n.type === 'warning' ? 'bg-amber-500' : n.type === 'error' ? 'bg-red-500' : 'bg-blue-500'
                      }`} />
                      <div>
                        <p className="text-sm font-medium text-gray-800">{n.title}</p>
                        <p className="text-xs text-gray-400 mt-0.5">{n.desc}</p>
                        <p className="text-[10px] text-gray-300 mt-1">{n.time}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="relative" ref={profileRef}>
          <button
            onClick={() => setProfileOpen(!profileOpen)}
            className="flex items-center gap-2 p-1.5 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <div className="w-7 h-7 bg-gray-800 rounded-full flex items-center justify-center">
              <span className="text-white text-xs font-medium">{avatarLabel}</span>
            </div>
          </button>
          {profileOpen && (
            <div className="absolute right-0 top-full mt-2 w-56 bg-white rounded-xl border border-gray-200 shadow-xl overflow-hidden">
              <div className="px-4 py-3 border-b border-gray-200">
                <p className="text-sm font-medium text-gray-900">当前账号</p>
                <p className="text-xs text-gray-400">{displayEmail}</p>
              </div>
              <div className="py-1">
                <button className="w-full px-4 py-2 text-left text-sm text-gray-600 hover:bg-gray-50 transition-colors">个人设置</button>
                <button className="w-full px-4 py-2 text-left text-sm text-gray-600 hover:bg-gray-50 transition-colors">API 密钥</button>
                <button className="w-full px-4 py-2 text-left text-sm text-gray-600 hover:bg-gray-50 transition-colors">帮助文档</button>
              </div>
              <div className="border-t border-gray-200 py-1">
                <button onClick={handleLogout} className="w-full px-4 py-2 text-left text-sm text-red-600 hover:bg-red-50 transition-colors flex items-center gap-2">
                  <IconLogOut size={14} /> 退出登录
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
