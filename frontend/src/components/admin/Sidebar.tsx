import { useNavigate, useLocation } from 'react-router-dom';
import {
  IconUsers, IconBuilding, IconShield, IconKey,
  IconMonitor, IconMail, IconFileText, IconSettings,
} from './Icons';

const sidebarGroups = [
  {
    title: '身份与访问',
    items: [
      { id: 'users', label: '用户管理', icon: IconUsers, path: '/admin/users' },
      { id: 'tenants', label: '租户管理', icon: IconBuilding, path: '/admin/tenants' },
      { id: 'roles', label: '角色与权限', icon: IconShield, path: '/admin/roles' },
    ],
  },
  {
    title: '应用与安全',
    items: [
      { id: 'oauth', label: 'OAuth Clients', icon: IconKey, path: '/admin/oauth' },
      { id: 'sessions', label: '会话管理', icon: IconMonitor, path: '/admin/sessions' },
      { id: 'security', label: '邮件与安全', icon: IconMail, path: '/admin/security' },
    ],
  },
  {
    title: '运维',
    items: [
      { id: 'audit', label: '审计日志', icon: IconFileText, path: '/admin/audit' },
      { id: 'settings', label: '系统设置', icon: IconSettings, path: '/admin/settings' },
    ],
  },
];

export default function Sidebar() {
  const navigate = useNavigate();
  const location = useLocation();

  return (
    <aside className="fixed left-0 top-[72px] w-[250px] h-[calc(100vh-72px)] bg-surface-muted border-r border-line overflow-y-auto z-40">
      <div className="py-4">
        {sidebarGroups.map((group, gi) => (
          <div key={gi} className="mb-2">
            <div className="px-4 py-2 text-[10px] font-semibold text-ink-tertiary uppercase tracking-wider">
              {group.title}
            </div>
            <nav className="px-2">
              {group.items.map((item) => {
                const isActive = location.pathname === item.path;
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    onClick={() => navigate(item.path)}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm transition-all duration-200 group ${
                      isActive
                        ? 'bg-surface text-ink shadow-soft-sm'
                        : 'text-ink-secondary hover:text-ink hover:bg-surface-hover'
                    }`}
                  >
                    <Icon size={17} className={isActive ? 'text-ink' : 'text-ink-tertiary group-hover:text-ink-secondary'} />
                    <span className="font-medium">{item.label}</span>
                  </button>
                );
              })}
            </nav>
          </div>
        ))}
      </div>
    </aside>
  );
}
