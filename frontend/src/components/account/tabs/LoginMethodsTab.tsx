import { useState } from 'react';
import {
  bindLoginMethod,
  unbindLoginMethod,
  changeAccountPassword,
} from '../../../api/account';
import AccountModal from '../AccountModal';
import {
  IconLock,
  IconMail,
  IconGithub,
  IconGoogle,
  IconMicrosoft,
  IconBuilding,
  IconPlus,
  IconUnlink,
  IconLink,
  IconClock,
  IconAlertTriangle,
  IconCheck,
  IconX,
} from '../../admin/Icons';
import type { SharedTabProps } from './types';
import type { LoginMethod } from '../../../types/account';

const ICON_MAP: Record<string, typeof IconLock> = {
  password: IconLock,
  email: IconMail,
  github: IconGithub,
  google: IconGoogle,
  microsoft: IconMicrosoft,
  sso: IconBuilding,
};

export default function LoginMethodsTab({ loginMethods, setLoginMethods, showToast }: SharedTabProps) {
  const [modal, setModal] = useState<{ type: string; method?: LoginMethod } | null>(null);
  const [loadingId, setLoadingId] = useState<string | null>(null);
  const [passwordForm, setPasswordForm] = useState({ current: '', newPass: '', confirm: '' });
  const [changingPassword, setChangingPassword] = useState(false);

  const handleBind = async (id: string) => {
    setLoadingId(id);
    try {
      await bindLoginMethod(id);
      setLoginMethods((ms) =>
        ms.map((m) =>
          m.id === id
            ? { ...m, bound: true, status: m.id === 'google' || m.id === 'microsoft' ? 'bound' : 'verified', lastUsed: '刚刚' }
            : m
        )
      );
      showToast('登录方式已绑定', 'success');
    } catch {
      showToast('绑定失败，请重试', 'error');
    } finally {
      setLoadingId(null);
    }
  };

  const handleUnbind = async (id: string) => {
    try {
      await unbindLoginMethod(id);
      setLoginMethods((ms) =>
        ms.map((m) => (m.id === id ? { ...m, bound: false, status: 'unbound' as const, lastUsed: null } : m))
      );
      showToast('已解绑', 'info');
      setModal(null);
    } catch {
      showToast('解绑失败', 'error');
    }
  };

  const handleChangePassword = async () => {
    if (passwordForm.newPass !== passwordForm.confirm) {
      showToast('两次输入不一致', 'error');
      return;
    }
    setChangingPassword(true);
    try {
      await changeAccountPassword({ current: passwordForm.current, newPass: passwordForm.newPass });
      showToast('密码已更新', 'success');
      setModal(null);
      setPasswordForm({ current: '', newPass: '', confirm: '' });
    } catch {
      showToast('修改失败', 'error');
    } finally {
      setChangingPassword(false);
    }
  };

  return (
    <div className="space-y-5">
      <div className="rounded-[20px] border border-line bg-surface-solid p-6 shadow-soft-sm">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-ink">登录方式</h2>
            <p className="mt-1 text-sm text-ink-tertiary">绑定越多，登录越灵活</p>
          </div>
          <span className="rounded-full bg-surface-hover px-3 py-1 text-xs font-medium text-ink-secondary">
            {loginMethods.filter((m) => m.bound).length}/{loginMethods.length} 已绑定
          </span>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {loginMethods.map((m) => {
            const Icon = ICON_MAP[m.id] || IconLock;
            const statusText =
              m.status === 'primary' ? '主登录方式' : m.status === 'verified' ? '已绑定' : m.bound ? '已绑定' : '未绑定';
            const statusColor =
              m.status === 'primary' || m.status === 'verified'
                ? 'bg-ok-soft text-ok'
                : m.bound
                  ? 'bg-surface-hover text-ink-secondary'
                  : 'bg-surface-hover text-ink-tertiary';
            const accentColor =
              { password: '#1A1A1A', email: '#B8865A', github: '#3A3A38', google: '#9A4848', microsoft: '#2B3A55', sso: '#6B6A65' }[
                m.id
              ] || 'var(--accent)';
            const isLoading = loadingId === m.id;

            return (
              <div
                key={m.id}
                className={`relative overflow-hidden rounded-2xl border border-line bg-surface-muted p-5 transition-all hover:shadow-soft-sm ${m.disabled ? 'opacity-50' : ''}`}
              >
                <div className="absolute left-0 top-0 h-full w-1 rounded-l-2xl" style={{ background: accentColor, opacity: m.bound ? 1 : 0.3 }} />
                <div className="flex items-start gap-4">
                  <div className="inline-flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-surface-hover text-ink">
                    <Icon size={20} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-baseline justify-between gap-2">
                      <span className="text-sm font-medium">{m.name}</span>
                      <span className={`shrink-0 rounded-full px-2 py-0.5 text-[11px] font-medium ${statusColor}`}>{statusText}</span>
                    </div>
                    <p className="mt-1 text-xs leading-relaxed text-ink-tertiary">{m.desc}</p>
                    {m.lastUsed && (
                      <div className="mt-2 flex items-center gap-1 text-[11px] text-ink-muted">
                        <IconClock size={12} />
                        上次使用：{m.lastUsed}
                      </div>
                    )}
                    <div className="mt-3 flex flex-wrap gap-2">
                      {m.bound ? (
                        <>
                          {m.id === 'password' && !m.disabled && (
                            <button
                              onClick={() => { setModal({ type: 'changePassword' }); }}
                              className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium text-ink-secondary transition-colors hover:bg-surface-hover"
                            >
                              <IconLock size={12} />
                              修改密码
                            </button>
                          )}
                          {!m.disabled && m.id !== 'email' && (
                            <button
                              onClick={() => setModal({ type: 'unbind', method: m })}
                              className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium text-danger transition-colors hover:bg-danger-soft"
                            >
                              <IconUnlink size={12} />
                              解绑
                            </button>
                          )}
                          {m.disabled && m.disabledReason && (
                            <span className="inline-flex items-center rounded-full bg-surface-hover px-3 py-1.5 text-[11px] font-medium text-ink-tertiary">
                              {m.disabledReason}
                            </span>
                          )}
                        </>
                      ) : (
                        <button
                          onClick={() => handleBind(m.id)}
                          disabled={isLoading || m.disabled}
                          className="inline-flex items-center gap-1.5 rounded-xl bg-ink px-4 py-2 text-xs font-medium text-ink-inverse transition-colors hover:bg-ink-secondary disabled:opacity-40"
                        >
                          {isLoading ? (
                            <span className="h-3 w-3 animate-spin rounded-full border-2 border-ink-inverse/30 border-t-ink-inverse" />
                          ) : (
                            <IconPlus size={12} />
                          )}
                          {m.disabled ? m.disabledReason : '绑定'}
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="flex flex-col items-center py-8 text-center">
        <div className="mb-3 inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-surface-muted text-ink-tertiary">
          <IconLink size={24} />
        </div>
        <p className="text-base font-medium">绑定新登录方式</p>
        <p className="mt-1 max-w-sm text-sm text-ink-tertiary">
          你可以把常用第三方账号绑定过来，以后一键登录，不需要再记密码。
        </p>
      </div>

      {/* Unbind confirm modal */}
      <AccountModal open={modal?.type === 'unbind'} onClose={() => setModal(null)}>
        {modal?.method && (
          <div>
            <div className="flex items-center gap-3">
              <div className="inline-flex h-10 w-10 items-center justify-center rounded-xl bg-danger-soft text-danger">
                <IconAlertTriangle size={18} />
              </div>
              <div>
                <div className="text-lg font-semibold">确认解绑？</div>
                <div className="text-sm text-ink-tertiary">操作不可撤销，请确认是你本人</div>
              </div>
            </div>
            <div className="mt-5 rounded-2xl border border-danger/20 bg-danger-soft p-4">
              <div className="flex items-center gap-2 text-sm font-medium text-danger">
                <IconAlertTriangle size={14} />
                风险提示
              </div>
              <div className="mt-2 text-xs leading-relaxed text-ink-secondary">
                解绑「{modal.method.name}」后，你将不再能用它来登录。如果这是你唯一绑定的登录方式，解绑后可能会导致无法进入账号。建议先绑定至少另一种方式。
              </div>
            </div>
            <div className="mt-6 flex justify-end gap-2">
              <button onClick={() => setModal(null)} className="rounded-xl px-4 py-2.5 text-sm font-medium text-ink-secondary transition-colors hover:bg-surface-hover">
                <IconX size={14} className="inline mr-1" />
                取消
              </button>
              <button
                onClick={() => handleUnbind(modal.method!.id)}
                className="inline-flex items-center gap-2 rounded-xl bg-danger px-5 py-2.5 text-sm font-medium text-ink-inverse transition-colors hover:bg-danger-strong"
              >
                <IconUnlink size={14} />
                确认解绑
              </button>
            </div>
          </div>
        )}
      </AccountModal>

      {/* Change password modal */}
      <AccountModal open={modal?.type === 'changePassword'} onClose={() => setModal(null)} title="修改密码">
        <div className="space-y-4">
          <div>
            <label className="mb-1.5 block text-sm font-medium">当前密码</label>
            <input
              type="password"
              className="w-full rounded-xl border border-line bg-surface-muted px-4 py-3 text-sm outline-none transition-all focus:border-brand focus:ring-2 focus:ring-brand-glow"
              placeholder="请输入当前密码"
              value={passwordForm.current}
              onChange={(e) => setPasswordForm((f) => ({ ...f, current: e.target.value }))}
            />
          </div>
          <div>
            <label className="mb-1.5 block text-sm font-medium">新密码</label>
            <input
              type="password"
              className="w-full rounded-xl border border-line bg-surface-muted px-4 py-3 text-sm outline-none transition-all focus:border-brand focus:ring-2 focus:ring-brand-glow"
              placeholder="至少 8 位，包含字母和数字"
              value={passwordForm.newPass}
              onChange={(e) => setPasswordForm((f) => ({ ...f, newPass: e.target.value }))}
            />
          </div>
          <div>
            <label className="mb-1.5 block text-sm font-medium">确认新密码</label>
            <input
              type="password"
              className="w-full rounded-xl border border-line bg-surface-muted px-4 py-3 text-sm outline-none transition-all focus:border-brand focus:ring-2 focus:ring-brand-glow"
              placeholder="再次输入新密码"
              value={passwordForm.confirm}
              onChange={(e) => setPasswordForm((f) => ({ ...f, confirm: e.target.value }))}
            />
            {passwordForm.confirm && passwordForm.confirm !== passwordForm.newPass && (
              <p className="mt-1.5 text-xs text-danger">两次输入不一致</p>
            )}
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button onClick={() => setModal(null)} className="rounded-xl px-4 py-2.5 text-sm font-medium text-ink-secondary transition-colors hover:bg-surface-hover">
              取消
            </button>
            <button
              onClick={handleChangePassword}
              disabled={
                changingPassword ||
                !passwordForm.current ||
                passwordForm.newPass.length < 6 ||
                passwordForm.newPass !== passwordForm.confirm
              }
              className="inline-flex items-center gap-2 rounded-xl bg-ink px-5 py-2.5 text-sm font-medium text-ink-inverse transition-colors hover:bg-ink-secondary disabled:opacity-40"
            >
              {changingPassword ? (
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-ink-inverse/30 border-t-ink-inverse" />
              ) : (
                <IconCheck size={14} />
              )}
              {changingPassword ? '保存中' : '保存'}
            </button>
          </div>
        </div>
      </AccountModal>
    </div>
  );
}
