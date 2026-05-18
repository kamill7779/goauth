import { useState } from 'react';
import { revokeAppAuthorization } from '../../../api/account';
import AccountModal from '../AccountModal';
import {
  IconApps,
  IconEye,
  IconUnlink,
  IconGlobe,
} from '../../admin/Icons';
import type { SharedTabProps } from './types';
import type { AuthorizedApp } from '../../../types/account';

export default function AuthorizedAppsTab({ authorizedApps, setAuthorizedApps, showToast }: SharedTabProps) {
  const [detailApp, setDetailApp] = useState<AuthorizedApp | null>(null);
  const [revokeApp, setRevokeApp] = useState<AuthorizedApp | null>(null);

  const handleRevoke = async (app: AuthorizedApp) => {
    try {
      await revokeAppAuthorization(app.id);
      setAuthorizedApps((list) => list.filter((a) => a.id !== app.id));
      showToast(`已撤销对「${app.name}」的授权`, 'info');
      setRevokeApp(null);
    } catch {
      showToast('撤销失败', 'error');
    }
  };

  if (authorizedApps.length === 0) {
    return (
      <div className="flex flex-col items-center rounded-[20px] border border-line bg-surface-solid py-16 text-center shadow-soft-sm">
        <div className="mb-4 inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-surface-muted text-ink-tertiary">
          <IconApps size={24} />
        </div>
        <p className="text-base font-medium">暂无已授权应用</p>
        <p className="mt-1 max-w-sm text-sm text-ink-tertiary">
          你还没有通过统一身份登录过任何接入应用。当你首次登录时，它们会出现在这里。
        </p>
        <button className="mt-5 inline-flex items-center gap-2 rounded-xl border border-line bg-surface-muted px-5 py-2.5 text-sm font-medium transition-colors hover:bg-surface-hover">
          <IconGlobe size={14} /> 浏览可用应用
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div className="rounded-[20px] border border-line bg-surface-solid p-6 shadow-soft-sm">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-ink">已授权应用</h2>
            <p className="mt-1 text-sm text-ink-tertiary">你可以随时查看或撤销任何应用对你的授权</p>
          </div>
          <span className="rounded-full bg-surface-hover px-3 py-1 text-xs font-medium text-ink-secondary">
            {authorizedApps.length} 个应用
          </span>
        </div>

        <div className="space-y-3">
          {authorizedApps.map((app) => (
            <div key={app.id} className="flex flex-col gap-4 rounded-2xl border border-line bg-surface-muted p-5 sm:flex-row sm:items-center">
              <div className="flex items-center gap-4">
                <div
                  className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl text-xl font-medium text-white"
                  style={{
                    background: app.color,
                    fontFamily: '"Newsreader", serif',
                    fontStyle: 'italic',
                  }}
                >
                  {app.initial}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline gap-2">
                    <span className="text-sm font-medium">{app.name}</span>
                    <span className="text-xs text-ink-tertiary">上次访问 {app.lastAccess}</span>
                  </div>
                  <div className="mt-0.5 text-xs leading-relaxed text-ink-tertiary">{app.desc}</div>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {app.scopes.map((s) => (
                      <span key={s} className="rounded-full bg-brand-soft px-2 py-0.5 text-[11px] font-medium text-brand">
                        {s}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
              <div className="flex shrink-0 gap-2">
                <button
                  onClick={() => setDetailApp(app)}
                  className="inline-flex items-center gap-1.5 rounded-xl px-3 py-2 text-xs font-medium text-ink-secondary transition-colors hover:bg-surface-hover"
                >
                  <IconEye size={12} /> 详情
                </button>
                <button
                  onClick={() => setRevokeApp(app)}
                  className="inline-flex items-center gap-1.5 rounded-xl px-3 py-2 text-xs font-medium text-danger transition-colors hover:bg-danger-soft"
                >
                  <IconUnlink size={12} /> 撤销
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Detail modal */}
      <AccountModal open={!!detailApp} onClose={() => setDetailApp(null)} title={detailApp?.name}>
        {detailApp && (
          <div className="space-y-4">
            <div className="flex items-center gap-4">
              <div
                className="flex h-14 w-14 items-center justify-center rounded-2xl text-xl font-medium text-white"
                style={{
                  background: detailApp.color,
                  fontFamily: '"Newsreader", serif',
                  fontStyle: 'italic',
                }}
              >
                {detailApp.initial}
              </div>
              <div>
                <div className="text-lg font-semibold">{detailApp.name}</div>
                <div className="text-sm text-ink-tertiary">{detailApp.desc}</div>
              </div>
            </div>
            <div className="h-px bg-line" />
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-sm text-ink-secondary">首次授权</span>
                <span className="text-sm font-medium">{detailApp.grantedAt}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-ink-secondary">最近访问</span>
                <span className="text-sm font-medium">{detailApp.lastAccess}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-ink-secondary">可访问的范围</span>
                <div className="flex gap-1.5">
                  {detailApp.scopes.map((s) => (
                    <span key={s} className="rounded-full bg-brand-soft px-2 py-0.5 text-[11px] font-medium text-brand">{s}</span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </AccountModal>

      {/* Revoke confirm modal */}
      <AccountModal open={!!revokeApp} onClose={() => setRevokeApp(null)}>
        {revokeApp && (
          <div>
            <div className="flex items-center gap-3">
              <div className="inline-flex h-10 w-10 items-center justify-center rounded-xl bg-danger-soft text-danger">
                <IconUnlink size={18} />
              </div>
              <div>
                <div className="text-lg font-semibold">撤销「{revokeApp.name}」的授权？</div>
                <div className="text-sm text-ink-tertiary">撤销后该应用将无法再读取你的信息</div>
              </div>
            </div>
            <div className="mt-5 rounded-2xl border border-line bg-surface-muted p-4 text-sm leading-relaxed text-ink-secondary">
              撤销授权后，该应用将不再能够访问你的头像、昵称、邮箱等资料。但它可能仍保留了你此前提供的本地数据。如果你只想暂时断开，可以直接退出该应用，不必撤销授权。
            </div>
            <div className="mt-6 flex justify-end gap-2">
              <button onClick={() => setRevokeApp(null)} className="rounded-xl px-4 py-2.5 text-sm font-medium text-ink-secondary transition-colors hover:bg-surface-hover">
                先不撤销
              </button>
              <button
                onClick={() => handleRevoke(revokeApp)}
                className="inline-flex items-center gap-2 rounded-xl bg-danger px-5 py-2.5 text-sm font-medium text-ink-inverse transition-colors hover:bg-danger-strong"
              >
                <IconUnlink size={14} /> 确认撤销
              </button>
            </div>
          </div>
        )}
      </AccountModal>
    </div>
  );
}
