import { useState } from 'react';

interface SettingItem {
  label: string;
  description: string;
  enabled: boolean;
}

interface SettingGroup {
  section: string;
  items: SettingItem[];
}

export default function SettingsPage() {
  const [settings, setSettings] = useState<SettingGroup[]>([
    {
      section: '身份认证',
      items: [
        { label: '允许公开注册', description: '是否允许用户自主注册账号', enabled: true },
        { label: '强制 MFA', description: '所有管理员账号必须启用多因素认证', enabled: false },
        { label: 'SSO 自动登录', description: '已登录企业 SSO 时自动跳转', enabled: true },
      ],
    },
    {
      section: '安全策略',
      items: [
        { label: '密码复杂度检查', description: '要求密码包含大小写字母、数字和特殊字符', enabled: true },
        { label: '会话超时时间', description: '无操作 8 小时后自动注销', enabled: true },
        { label: '登录失败锁定', description: '连续 5 次失败锁定账号 30 分钟', enabled: true },
      ],
    },
    {
      section: '审计与合规',
      items: [
        { label: '详细审计日志', description: '记录所有 API 调用和管理操作', enabled: true },
        { label: '日志保留期限', description: '审计日志保留 365 天', enabled: true },
      ],
    },
  ]);

  const toggleSetting = (gi: number, ii: number) => {
    setSettings(prev => {
      const next = [...prev];
      next[gi] = { ...next[gi], items: [...next[gi].items] };
      next[gi].items[ii] = { ...next[gi].items[ii], enabled: !next[gi].items[ii].enabled };
      return next;
    });
  };

  return (
    <div className="animate-[fadeInUp_0.4s_ease]">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-ink mb-1">系统设置</h1>
        <p className="text-sm text-ink-tertiary">配置 GoAuth 全局策略、安全规则和默认行为</p>
      </div>

      <div className="max-w-2xl space-y-6">
        {settings.map((group, gi) => (
          <div key={gi} className="bg-surface-solid rounded-xl border border-line overflow-hidden">
            <div className="px-5 py-3.5 border-b border-line bg-surface-muted">
              <h2 className="text-sm font-semibold text-ink">{group.section}</h2>
            </div>
            <div className="divide-y divide-line">
              {group.items.map((item, ii) => (
                <div key={ii} className="px-5 py-4 flex items-center justify-between hover:bg-surface-hover transition-colors">
                  <div>
                    <p className="text-sm font-medium text-ink">{item.label}</p>
                    <p className="text-xs text-ink-tertiary mt-0.5">{item.description}</p>
                  </div>
                  <button
                    onClick={() => toggleSetting(gi, ii)}
                    className="relative w-11 h-6 rounded-full transition-colors"
                    style={{ background: item.enabled ? 'var(--accent)' : 'var(--border-strong)' }}
                  >
                    <div
                      className="absolute top-0.5 w-5 h-5 rounded-full shadow-soft-sm transition-transform"
                      style={{
                        background: 'var(--surface-solid)',
                        transform: item.enabled ? 'translateX(20px)' : 'translateX(2px)',
                      }}
                    />
                  </button>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
