import { useState, useRef, useEffect } from 'react';
import {
  updateAccountProfile,
  uploadAccountAvatar,
  removeAccountAvatar,
} from '../../../api/account';
import {
  IconCamera,
  IconUpload,
  IconTrash,
  IconCheck,
  IconRefreshCw,
  IconGlobe,
} from '../../admin/Icons';
import type { SharedTabProps } from './types';

export default function ProfileTab({ user, showToast, refresh }: SharedTabProps) {
  const avatarUploadEnabled = false;
  const timezoneEditable = false;
  const emailEditable = false;
  const [form, setForm] = useState({
    name: user.display_name || user.nickname || '',
    username: user.username,
    email: user.email,
    locale: user.locale || 'zh-CN',
    timezone: user.timezone || 'Asia/Shanghai',
  });
  const [saving, setSaving] = useState(false);
  const [avatarHover, setAvatarHover] = useState(false);
  const [dirty, setDirty] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setForm({
      name: user.display_name || user.nickname || '',
      username: user.username,
      email: user.email,
      locale: user.locale || 'zh-CN',
      timezone: user.timezone || 'Asia/Shanghai',
    });
    setDirty(false);
  }, [user]);

  const update = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    setForm((f) => ({ ...f, [k]: e.target.value }));
    setDirty(true);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateAccountProfile({
        nickname: form.name,
        display_name: form.name,
        username: form.username,
        email: form.email,
        locale: form.locale,
        timezone: form.timezone,
      });
      showToast('资料已保存', 'success');
      setDirty(false);
      refresh();
    } catch {
      showToast('保存失败，请重试', 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    setForm({
      name: user.display_name || user.nickname || '',
      username: user.username,
      email: user.email,
      locale: user.locale || 'zh-CN',
      timezone: user.timezone || 'Asia/Shanghai',
    });
    setDirty(false);
    showToast('已撤销未保存的修改', 'info');
  };

  const handlePickAvatar = () => {
    if (!avatarUploadEnabled) {
      showToast('头像上传入口暂未开放', 'info');
      return;
    }
    fileRef.current?.click();
  };
  const handleAvatarFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      await uploadAccountAvatar(file);
      showToast('头像已更新', 'success');
      refresh();
    } catch {
      showToast('头像上传失败', 'error');
    }
  };
  const handleRemoveAvatar = async () => {
    if (!user.avatar_url) {
      showToast('当前没有自定义头像', 'info');
      return;
    }
    try {
      await removeAccountAvatar();
      showToast('头像已移除', 'success');
      refresh();
    } catch {
      showToast('操作失败', 'error');
    }
  };

  const initials = (form.name || user.username || '?').slice(0, 1);

  return (
    <div className="grid grid-cols-1 gap-5 lg:grid-cols-[1.4fr_1fr]">
      {/* Form card */}
      <div className="rounded-[20px] border border-line bg-surface-solid p-7 shadow-soft-sm">
        <div className="mb-6">
          <h2 className="text-lg font-semibold text-ink">个人资料</h2>
          <p className="mt-1 text-sm text-ink-tertiary">这些信息会出现在你授权过的应用中</p>
        </div>

        {/* Avatar */}
        <div className="flex items-center gap-5 border-b border-line pb-6">
          <div
            className={`relative ${avatarUploadEnabled ? 'cursor-pointer' : 'cursor-default'}`}
            onMouseEnter={() => setAvatarHover(true)}
            onMouseLeave={() => setAvatarHover(false)}
            onClick={avatarUploadEnabled ? handlePickAvatar : undefined}
          >
            <div className="flex h-[88px] w-[88px] items-center justify-center rounded-full bg-gradient-to-br from-[#C99B6E] to-[#9A6E47] text-[28px] font-medium text-white shadow-lg"
              style={{ fontFamily: '"Newsreader", serif', fontStyle: 'italic' }}
            >
              {user.avatar_url ? <img src={user.avatar_url} alt="" className="h-full w-full rounded-full object-cover" /> : initials}
            </div>
            <div className={`absolute inset-0 flex items-center justify-center gap-1 rounded-full bg-ink/50 text-xs font-medium text-ink-inverse transition-opacity ${avatarHover && avatarUploadEnabled ? 'opacity-100' : 'opacity-0'}`}>
              <IconCamera size={14} />
              更换
            </div>
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-sm font-medium">头像</div>
            <div className="mt-1 text-xs leading-relaxed text-ink-tertiary">
              当前仅支持移除现有头像。上传入口会在对象存储接入后开放。
            </div>
            <div className="mt-3 flex gap-2">
              <button
                onClick={handlePickAvatar}
                disabled={!avatarUploadEnabled}
                className="inline-flex items-center gap-2 rounded-xl border border-line bg-surface-muted px-4 py-2 text-sm font-medium transition-colors hover:bg-surface-hover disabled:opacity-40"
              >
                <IconUpload size={14} /> 上传图片
              </button>
              <button onClick={handleRemoveAvatar} disabled={!user.avatar_url} className="inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-medium text-danger transition-colors hover:bg-danger-soft disabled:opacity-40">
                <IconTrash size={14} /> 移除
              </button>
            </div>
            <input ref={fileRef} type="file" accept="image/*" className="hidden" onChange={handleAvatarFile} />
          </div>
        </div>

        {/* Form fields */}
        <div className="mt-6 grid grid-cols-1 gap-5 sm:grid-cols-2">
          <div>
            <label className="mb-2 block text-sm font-medium text-ink">名字</label>
            <input className="w-full rounded-xl border border-line bg-surface-muted px-4 py-3 text-sm outline-none transition-all focus:border-brand focus:ring-2 focus:ring-brand-glow"
              value={form.name} onChange={update('name')} placeholder="对外展示的名称" />
            <p className="mt-1.5 text-xs text-ink-tertiary">登录后顶栏和授权应用中会显示这个名字</p>
          </div>
          <div>
            <div className="mb-2 flex items-center justify-between">
              <label className="text-sm font-medium text-ink">用户名</label>
              <span className="rounded-full bg-surface-hover px-2 py-0.5 text-[10px] font-medium text-ink-tertiary">不可频繁更改</span>
            </div>
            <div className="relative">
              <span className="absolute left-4 top-1/2 -translate-y-1/2 text-sm text-ink-muted">@</span>
              <input className="w-full rounded-xl border border-line bg-surface-muted px-4 py-3 pl-7 text-sm outline-none transition-all focus:border-brand focus:ring-2 focus:ring-brand-glow"
                value={form.username} onChange={update('username')} />
            </div>
          </div>
          <div>
            <div className="mb-2 flex items-center justify-between">
              <label className="text-sm font-medium text-ink">主邮箱</label>
              <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-medium ${user.email_verified ? 'bg-ok-soft text-ok' : 'bg-warn-soft text-warn'}`}>
                {user.email_verified ? '已验证' : '未验证'}
              </span>
            </div>
            <input type="email" className="w-full rounded-xl border border-line bg-surface-muted px-4 py-3 text-sm outline-none transition-all focus:border-brand focus:ring-2 focus:ring-brand-glow disabled:cursor-not-allowed disabled:opacity-70"
              value={form.email} onChange={update('email')} disabled={!emailEditable} />
            <p className="mt-1.5 text-xs text-ink-tertiary">用于接收安全通知和重置密码。邮箱换绑入口即将开放。</p>
          </div>
          <div>
            <label className="mb-2 block text-sm font-medium text-ink">语言</label>
            <select className="w-full rounded-xl border border-line bg-surface-muted px-4 py-3 text-sm outline-none transition-all focus:border-brand focus:ring-2 focus:ring-brand-glow"
              value={form.locale} onChange={update('locale')}>
              <option value="zh-CN">简体中文</option>
              <option value="en">English</option>
              <option value="ja">日本語</option>
            </select>
          </div>
          <div className="sm:col-span-2">
            <label className="mb-2 block text-sm font-medium text-ink">时区</label>
            <select className="w-full rounded-xl border border-line bg-surface-muted px-4 py-3 text-sm outline-none transition-all focus:border-brand focus:ring-2 focus:ring-brand-glow disabled:cursor-not-allowed disabled:opacity-70"
              value={form.timezone} onChange={update('timezone')} disabled={!timezoneEditable}>
              <option value="Asia/Shanghai">Asia/Shanghai (UTC+8)</option>
              <option value="Asia/Tokyo">Asia/Tokyo (UTC+9)</option>
              <option value="Europe/London">Europe/London (UTC+0)</option>
              <option value="America/Los_Angeles">America/Los_Angeles (UTC-8)</option>
            </select>
            <p className="mt-1.5 text-xs text-ink-tertiary">时区展示已预留，真实持久化稍后补齐。</p>
          </div>
        </div>

        <div className="mt-6 flex items-center justify-between border-t border-line pt-5">
          <span className="text-xs text-ink-tertiary">账号创建于 {user.created_at?.slice(0, 10)}</span>
          <div className="flex gap-2">
            <button onClick={handleReset} disabled={!dirty} className="inline-flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-medium text-ink-secondary transition-colors hover:bg-surface-hover disabled:opacity-40">
              <IconRefreshCw size={14} /> 重置
            </button>
            <button onClick={handleSave} disabled={!dirty || saving} className="inline-flex items-center gap-2 rounded-xl bg-ink px-5 py-2.5 text-sm font-medium text-ink-inverse transition-colors hover:bg-ink-secondary disabled:opacity-40">
              {saving ? (
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-ink-inverse/30 border-t-ink-inverse" />
              ) : (
                <IconCheck size={14} />
              )}
              {saving ? '保存中' : '保存修改'}
            </button>
          </div>
        </div>
      </div>

      {/* Preview sidebar */}
      <div className="space-y-5">
        <div className="rounded-[20px] border border-line bg-surface-solid p-6 shadow-soft-sm">
          <div className="mb-4">
            <h2 className="text-base font-semibold text-ink">公开资料预览</h2>
            <p className="mt-1 text-sm text-ink-tertiary">其他应用看到的你</p>
          </div>
          <div className="flex items-center gap-4 rounded-2xl border border-line bg-surface-muted p-4">
            <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-[#C99B6E] to-[#9A6E47] text-lg font-medium text-white"
              style={{ fontFamily: '"Newsreader", serif', fontStyle: 'italic' }}
            >
              {initials}
            </div>
            <div className="min-w-0">
              <div className="truncate text-sm font-medium">{form.name}</div>
              <div className="mt-0.5 truncate font-mono text-xs text-ink-tertiary">@{form.username}</div>
              <div className="mt-0.5 truncate text-xs text-ink-tertiary">{form.email}</div>
            </div>
          </div>
          <p className="mt-4 text-xs leading-relaxed text-ink-tertiary">
            授权某个应用读取你的资料后，它看到的就是这个样子。修改实时同步。
          </p>
        </div>

        <div className="rounded-[20px] border border-line bg-surface-solid p-6 shadow-soft-sm">
          <div className="flex items-center gap-3">
            <div className="inline-flex h-9 w-9 items-center justify-center rounded-xl bg-brand-soft text-brand">
              <IconGlobe size={16} />
            </div>
            <div className="text-sm font-medium">关于隐私</div>
          </div>
          <p className="mt-3 text-xs leading-relaxed text-ink-tertiary">
            只有你已经授权过的应用可以看到你的公开资料。撤销授权后，对应应用将无法再读取。
          </p>
        </div>
      </div>

      {/* Dirty sticky bar */}
      {dirty && (
        <div className="fixed bottom-6 left-1/2 z-40 flex -translate-x-1/2 items-center gap-4 rounded-2xl bg-ink px-5 py-3 text-sm font-medium text-ink-inverse shadow-soft-lg">
          <span className="h-2 w-2 animate-pulse rounded-full bg-brand" />
          <span>你有未保存的修改</span>
          <button onClick={handleReset} className="rounded-lg px-3 py-1.5 text-xs transition-colors hover:bg-white/10">撤销</button>
          <button onClick={handleSave} disabled={saving} className="rounded-lg bg-ink-inverse px-4 py-1.5 text-xs font-medium text-ink transition-colors disabled:opacity-50">
            {saving ? '保存中' : '保存'}
          </button>
        </div>
      )}
    </div>
  );
}
