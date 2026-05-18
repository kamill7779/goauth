import { useState, useMemo, useRef } from 'react';
import {
  revokeAccountSession,
  logoutAllAccountSessions,
  disable2FA,
  enable2FA,
  verify2FASetup,
  regenerateRecoveryCodes,
} from '../../../api/account';
import AccountModal from '../AccountModal';
import {
  IconShield,
  IconCheck,
  IconAlertTriangle,
  IconInfo,
  IconKey,
  IconRefreshCw,
  IconLogOut,
  IconMonitor,
  IconX,
  IconCheckCircle,
  IconDownload,
  IconCopy,
  IconEye,
  IconFingerprint,
  IconBell,
  IconUnlink,
  IconArrowRight,
} from '../../admin/Icons';
import type { SharedTabProps } from './types';
import type { AccountSession } from '../../../types/account';

function formatDate(value: string) {
  if (!value) return '-';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString('zh-CN', { hour12: false });
}

function statusLabel(status: string) {
  switch (status) {
    case 'active': return '活跃';
    case 'revoked': return '已下线';
    case 'expired': return '已过期';
    default: return '未活跃';
  }
}

function MockQRCode() {
  const cells = useMemo(() => {
    const size = 20;
    const arr: { i: number; j: number; filled: boolean }[] = [];
    for (let i = 0; i < size; i++) {
      for (let j = 0; j < size; j++) {
        const isCorner = (i < 5 && j < 5) || (i < 5 && j >= size - 5) || (i >= size - 5 && j < 5);
        const hash = Math.sin(i * 31.1 + j * 17.3) > 0;
        const filled = isCorner
          ? (i === 0 || i === 4 || j === 0 || j === 4) || (i >= 1 && i <= 3 && j >= 1 && j <= 3 && !(i === 2 && j === 2))
          : hash;
        arr.push({ i, j, filled });
      }
    }
    return arr;
  }, []);
  return (
    <div className="grid gap-px rounded-2xl border border-line bg-white p-3" style={{ gridTemplateColumns: 'repeat(20, 1fr)', width: 180, height: 180 }}>
      {cells.map((c) => (
        <div key={`${c.i}-${c.j}`} className={`rounded-[1px] ${c.filled ? 'bg-ink' : 'bg-transparent'}`} />
      ))}
    </div>
  );
}

export default function SecurityTab({
  user,
  sessions,
  loginMethods,
  twoFAEnabled,
  setTwoFAEnabled,
  securityScore,
  showToast,
  refresh,
}: SharedTabProps) {
  const [totpStep, setTotpStep] = useState(0);
  const [totpCode, setTotpCode] = useState(['', '', '', '', '', '']);
  const [showCodes, setShowCodes] = useState(true);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [busySessionId, setBusySessionId] = useState<string | null>(null);
  const [loggingOutAll, setLoggingOutAll] = useState(false);
  const [confirmDisable, setConfirmDisable] = useState(false);
  const codeRefs = useRef<(HTMLInputElement | null)[]>([]);

  const scoreColor = securityScore >= 80 ? 'text-ok' : securityScore >= 60 ? 'text-warn' : 'text-danger';
  const scoreHex = securityScore >= 80 ? 'var(--success)' : securityScore >= 60 ? 'var(--warning)' : 'var(--error)';

  const boundCount = loginMethods.filter((method) => method.bound).length;

  const visibleAlerts = [
    ...(!twoFAEnabled ? [{ level: 'warning' as const, title: '建议开启两步验证', desc: '开启后，你的安全等级可以从当前的 ' + securityScore + ' 分提升至 90 分以上。' }] : []),
    ...(boundCount < 2 ? [{ level: 'info' as const, title: '建议增加第二登录方式', desc: '当前仅绑定了 ' + boundCount + ' 种方式。万一密码丢失，多渠道登录能帮你尽快找回。' }] : []),
    ...(!user.email_verified ? [{ level: 'danger' as const, title: '邮箱尚未验证', desc: '未验证邮箱无法用于重置密码和接收安全通知。' }] : []),
    ...(twoFAEnabled && boundCount >= 2 && user.email_verified ? [{ level: 'success' as const, title: '你的账号安全措施很完善', desc: '两步验证已开启、至少有两种登录方式、邮箱已验证。保持现状即可。' }] : []),
  ];

  const handleCodeInput = (i: number, val: string) => {
    if (!/^\d?$/.test(val)) return;
    const next = [...totpCode];
    next[i] = val;
    setTotpCode(next);
    if (val && i < 5) codeRefs.current[i + 1]?.focus();
  };
  const handleCodeKey = (i: number, e: React.KeyboardEvent) => {
    if (e.key === 'Backspace' && !totpCode[i] && i > 0) codeRefs.current[i - 1]?.focus();
  };

  const startEnable = async () => {
    try {
      const { secret } = await enable2FA();
      console.log('2FA secret:', secret);
      setTotpStep(1);
    } catch (err) {
      showToast(err instanceof Error ? err.message : '获取二维码失败', 'error');
    }
  };

  const handleVerify = async () => {
    if (totpCode.join('').length !== 6) {
      showToast('请输入完整的 6 位验证码', 'error');
      return;
    }
    try {
      const { verified } = await verify2FASetup(totpCode.join(''));
      if (verified) {
        const { codes } = await regenerateRecoveryCodes();
        setRecoveryCodes(codes);
        setTotpStep(3);
        showToast('验证码正确，请保存恢复码', 'success');
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : '验证码错误', 'error');
    }
  };

  const handleFinish = () => {
    setTwoFAEnabled(true);
    setTotpStep(0);
    setTotpCode(['', '', '', '', '', '']);
    showToast('两步验证已开启，你的账号更安全了', 'success');
  };

  const handleDisable = async () => {
    try {
      await disable2FA();
      setTwoFAEnabled(false);
      setConfirmDisable(false);
      showToast('两步验证已关闭', 'info');
    } catch (err) {
      showToast(err instanceof Error ? err.message : '关闭失败', 'error');
    }
  };

  const handleRevokeSession = async (session: AccountSession) => {
    const confirmed = window.confirm(session.current ? '确认退出当前会话？' : '确认下线这个会话？');
    if (!confirmed) return;
    setBusySessionId(session.id);
    try {
      await revokeAccountSession(session.id);
      if (session.current) {
        window.localStorage.removeItem('access_token');
        window.localStorage.removeItem('refresh_token');
        window.location.href = '/login';
        return;
      }
      refresh();
    } catch (err) {
      showToast(err instanceof Error ? err.message : '下线失败', 'error');
    } finally {
      setBusySessionId(null);
    }
  };

  const handleLogoutAll = async () => {
    const confirmed = window.confirm('确认退出当前账号的所有会话？');
    if (!confirmed) return;
    setLoggingOutAll(true);
    try {
      await logoutAllAccountSessions();
      window.localStorage.removeItem('access_token');
      window.localStorage.removeItem('refresh_token');
      window.location.href = '/login';
    } catch (err) {
      showToast(err instanceof Error ? err.message : '退出所有会话失败', 'error');
      setLoggingOutAll(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* Security overview */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <div className="rounded-[20px] border border-line bg-surface-solid p-5 shadow-soft-sm">
          <div className="flex items-center justify-between">
            <span className="text-sm text-ink-secondary">两步验证</span>
            <span className={`h-2.5 w-2.5 rounded-full ${twoFAEnabled ? 'bg-ok' : 'bg-warn'} ${!twoFAEnabled ? 'animate-pulse' : ''}`} />
          </div>
          <div className={`mt-3 text-xl font-semibold ${twoFAEnabled ? 'text-ok' : 'text-warn'}`}>
            {twoFAEnabled ? '已开启' : '未开启'}
          </div>
          <div className="mt-1 text-xs text-ink-tertiary">
            {twoFAEnabled ? '双重锁保护中' : '建议开启，加一道锁'}
          </div>
        </div>
        <div className="rounded-[20px] border border-line bg-surface-solid p-5 shadow-soft-sm">
          <div className="text-sm text-ink-secondary">恢复码</div>
          <div className="mt-3 text-xl font-semibold text-ok">可用</div>
          <div className="mt-1 text-xs text-ink-tertiary">10 组，可随时重新生成</div>
        </div>
        <div className="rounded-[20px] border border-line bg-surface-solid p-5 shadow-soft-sm">
          <div className="text-sm text-ink-secondary">邮箱验证</div>
          <div className={`mt-3 text-xl font-semibold ${user.email_verified ? 'text-ok' : 'text-danger'}`}>
            {user.email_verified ? '已验证' : '未验证'}
          </div>
          <div className="mt-1 text-xs text-ink-tertiary">
            {user.email_verified ? '可收安全通知' : '验证后才能重设密码'}
          </div>
        </div>
        <div className="flex items-center gap-4 rounded-[20px] border border-line bg-surface-solid p-5 shadow-soft-sm">
          <div className="relative h-14 w-14">
            <svg viewBox="0 0 56 56" className="h-14 w-14" style={{ transform: 'rotate(-90deg)' }}>
              <circle cx="28" cy="28" r="24" fill="none" stroke="var(--border-strong)" strokeWidth={4} />
              <circle cx="28" cy="28" r="24" fill="none" stroke={scoreHex} strokeWidth={4} strokeLinecap="round"
                strokeDasharray={`${2 * Math.PI * 24}`}
                strokeDashoffset={`${2 * Math.PI * 24 * (1 - securityScore / 100)}`}
                style={{ transition: 'stroke-dashoffset 1.2s cubic-bezier(0.32, 0.72, 0, 1)' }}
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className={`text-lg font-semibold ${scoreColor}`}>{securityScore}</span>
            </div>
          </div>
          <div>
            <div className="text-sm text-ink-secondary">安全等级</div>
            <div className={`mt-1 text-sm font-medium ${scoreColor}`}>
              {securityScore >= 80 ? '优秀' : securityScore >= 60 ? '良好' : '需加强'}
            </div>
          </div>
        </div>
      </div>

      {/* 2FA Wizard */}
      {totpStep > 0 ? (
        <div className="rounded-[20px] border border-line bg-surface-solid p-7 shadow-soft-sm">
          <div className="mb-5 flex items-center gap-3">
            <div className="inline-flex h-9 w-9 items-center justify-center rounded-xl bg-brand-soft text-brand">
              <IconShield size={18} />
            </div>
            <div>
              <div className="font-semibold">开启两步验证</div>
              <div className="text-sm text-ink-tertiary">第 {totpStep} 步，共 3 步</div>
            </div>
          </div>
          <div className="mb-6 h-1 overflow-hidden rounded-full bg-surface-hover">
            <div className="h-full rounded-full bg-brand transition-all duration-500" style={{ width: `${(totpStep / 3) * 100}%` }} />
          </div>

          {totpStep === 1 && (
            <div className="flex flex-wrap gap-6">
              <div className="min-w-[200px] flex-1">
                <div className="font-medium">用身份验证器扫码</div>
                <div className="mt-2 text-sm leading-relaxed text-ink-secondary">
                  打开 Google Authenticator、Microsoft Authenticator 或其他 TOTP 应用，扫描下方二维码。你也可以在应用中手动输入密钥。
                </div>
                <div className="mt-4 flex items-center gap-3">
                  <code className="rounded-xl bg-surface-hover px-3 py-2 font-mono text-sm">JBSW Y3DP EHPK 3PXP</code>
                  <button onClick={() => showToast('密钥已复制', 'success')} className="rounded-lg px-2 py-1.5 text-xs text-ink-secondary hover:bg-surface-hover">
                    <IconCopy size={14} className="inline" /> 复制
                  </button>
                </div>
              </div>
              <MockQRCode />
            </div>
          )}

          {totpStep === 2 && (
            <div>
              <div className="font-medium">输入验证码确认绑定</div>
              <div className="mt-2 text-sm text-ink-secondary">打开手机上的验证器应用，输入显示的 6 位数字。</div>
              <div className="mt-5 flex justify-center gap-2">
                {[0, 1, 2, 3, 4, 5].map((i) => (
                  <input
                    key={i}
                    ref={(el) => { codeRefs.current[i] = el; }}
                    type="text"
                    inputMode="numeric"
                    maxLength={1}
                    className="h-14 w-12 rounded-xl border border-line bg-surface-muted text-center text-xl font-medium outline-none transition-all focus:border-brand focus:ring-2 focus:ring-brand-glow"
                    value={totpCode[i]}
                    onChange={(e) => handleCodeInput(i, e.target.value)}
                    onKeyDown={(e) => handleCodeKey(i, e)}
                  />
                ))}
              </div>
            </div>
          )}

          {totpStep === 3 && (
            <div>
              <div className="mb-4 flex items-center gap-2">
                <div className="inline-flex h-7 w-7 items-center justify-center rounded-full bg-ok-soft text-ok">
                  <IconCheck size={16} />
                </div>
                <span className="font-medium">绑定成功 — 请保存恢复码</span>
              </div>
              <div className="text-sm leading-relaxed text-ink-secondary">
                如果你更换了手机、删除了验证器应用或丢失了设备，恢复码是你唯一能在不借助两步验证的情况下恢复账号的方法。请将它们安全保存到离线位置，切勿与他人分享。
              </div>
              <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
                {recoveryCodes.map((code) => (
                  <div key={code} className="rounded-xl border border-dashed border-line bg-surface-muted px-3 py-2.5 text-center font-mono text-xs tracking-wider">
                    {showCodes ? code : '****-****-****'}
                  </div>
                ))}
              </div>
              <div className="mt-4 flex gap-2">
                <button onClick={() => setShowCodes((s) => !s)} className="inline-flex items-center gap-1.5 rounded-xl border border-line bg-surface-muted px-3 py-2 text-xs font-medium transition-colors hover:bg-surface-hover">
                  <IconEye size={12} /> {showCodes ? '隐藏' : '显示'}
                </button>
                <button onClick={() => showToast('恢复码已复制', 'success')} className="inline-flex items-center gap-1.5 rounded-xl border border-line bg-surface-muted px-3 py-2 text-xs font-medium transition-colors hover:bg-surface-hover">
                  <IconCopy size={12} /> 全部复制
                </button>
                <button onClick={() => showToast('已保存到下载文件夹', 'success')} className="inline-flex items-center gap-1.5 rounded-xl border border-line bg-surface-muted px-3 py-2 text-xs font-medium transition-colors hover:bg-surface-hover">
                  <IconDownload size={12} /> 下载文本文件
                </button>
              </div>
            </div>
          )}

          <div className="mt-8 flex justify-between gap-3">
            <button onClick={() => { setTotpStep(0); setTotpCode(['', '', '', '', '', '']); }} className="rounded-xl px-4 py-2.5 text-sm font-medium text-ink-secondary transition-colors hover:bg-surface-hover">
              <IconX size={14} className="inline mr-1" /> 取消
            </button>
            {totpStep === 1 && (
              <button onClick={() => setTotpStep(2)} className="inline-flex items-center gap-2 rounded-xl bg-ink px-5 py-2.5 text-sm font-medium text-ink-inverse transition-colors hover:bg-ink-secondary">
                <IconArrowRight size={14} /> 我已扫码
              </button>
            )}
            {totpStep === 2 && (
              <button onClick={handleVerify} className="inline-flex items-center gap-2 rounded-xl bg-ink px-5 py-2.5 text-sm font-medium text-ink-inverse transition-colors hover:bg-ink-secondary">
                <IconCheck size={14} /> 确认绑定
              </button>
            )}
            {totpStep === 3 && (
              <button onClick={handleFinish} className="inline-flex items-center gap-2 rounded-xl bg-ink px-5 py-2.5 text-sm font-medium text-ink-inverse transition-colors hover:bg-ink-secondary">
                <IconCheck size={14} /> 我保存好了
              </button>
            )}
          </div>
        </div>
      ) : (
        <div className="rounded-[20px] border border-line bg-surface-solid p-7 shadow-soft-sm">
          <div className="mb-4">
            <h2 className="text-lg font-semibold text-ink">两步验证</h2>
            <p className="mt-1 text-sm text-ink-tertiary">密码泄露时的第二道防线</p>
          </div>
          {twoFAEnabled ? (
            <div className="flex flex-wrap items-center gap-4">
              <div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-ok-soft text-ok">
                <IconCheckCircle size={24} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="font-medium">已开启两步验证</div>
                <div className="text-sm text-ink-secondary">当前通过 TOTP 应用验证第二重身份。恢复码可用，建议定期重新生成。</div>
              </div>
              <div className="flex gap-2">
                <button onClick={async () => { try { const { codes } = await regenerateRecoveryCodes(); setRecoveryCodes(codes); showToast('恢复码已重新生成', 'success'); } catch (err) { showToast(err instanceof Error ? err.message : '操作失败', 'error'); } }} className="rounded-xl px-4 py-2.5 text-sm font-medium text-ink-secondary transition-colors hover:bg-surface-hover">
                  <IconRefreshCw size={14} className="inline mr-1" /> 重新生成恢复码
                </button>
                <button onClick={() => setConfirmDisable(true)} className="rounded-xl px-4 py-2.5 text-sm font-medium text-danger transition-colors hover:bg-danger-soft">
                  <IconUnlink size={14} className="inline mr-1" /> 关闭
                </button>
              </div>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-4">
              <div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-warn-soft text-warn">
                <IconAlertTriangle size={24} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="font-medium">尚未开启两步验证</div>
                <div className="text-sm text-ink-secondary">开启后，每次登录除了输入密码，还需要输入手机上的一次性验证码。即使密码泄露，攻击者也无法进入你的账号。</div>
              </div>
              <button onClick={startEnable} className="inline-flex items-center gap-2 rounded-xl bg-ink px-5 py-2.5 text-sm font-medium text-ink-inverse transition-colors hover:bg-ink-secondary">
                <IconShield size={16} /> 立即开启
              </button>
            </div>
          )}
        </div>
      )}

      {/* Sessions */}
      <div className="rounded-[20px] border border-line bg-surface-solid p-6 shadow-soft-sm">
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-ink">活跃会话</h2>
            <p className="mt-1 text-sm text-ink-tertiary">查看当前账号的登录会话，并下线不再使用的设备。</p>
          </div>
          <div className="flex gap-2">
            <button onClick={refresh} className="inline-flex items-center gap-2 rounded-xl border border-line bg-surface-muted px-4 py-2 text-sm font-medium text-ink-secondary transition-colors hover:bg-surface-hover">
              <IconRefreshCw size={14} /> 刷新
            </button>
            <button onClick={handleLogoutAll} disabled={loggingOutAll} className="inline-flex items-center gap-2 rounded-xl bg-danger px-4 py-2 text-sm font-medium text-ink-inverse transition-colors hover:bg-danger-strong disabled:opacity-50">
              <IconLogOut size={14} /> 退出所有会话
            </button>
          </div>
        </div>
        {sessions.length === 0 ? (
          <div className="flex flex-col items-center py-12 text-center">
            <IconMonitor size={24} className="mb-3 text-ink-tertiary" />
            <p className="text-sm font-medium">暂无会话记录</p>
          </div>
        ) : (
          <div className="space-y-3">
            {sessions.map((session) => (
              <div key={session.id} className="flex flex-col gap-4 rounded-2xl border border-line bg-surface-muted p-4 sm:flex-row sm:items-center">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate text-sm font-medium">{session.client || 'GoAuth'}</span>
                    {session.current && <span className="rounded-full bg-brand-soft px-2 py-0.5 text-xs font-medium text-brand">当前会话</span>}
                    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${session.status === 'active' ? 'bg-ok-soft text-ok' : session.status === 'revoked' ? 'bg-danger-soft text-danger' : 'bg-surface-hover text-ink-tertiary'}`}>
                      {statusLabel(session.status)}
                    </span>
                  </div>
                  <div className="mt-2 grid gap-1 text-xs text-ink-tertiary sm:grid-cols-2 lg:grid-cols-4">
                    <span className="truncate">IP：{session.ip || '-'}</span>
                    <span className="truncate">创建：{formatDate(session.created_at)}</span>
                    <span className="truncate">过期：{formatDate(session.expires_at)}</span>
                  </div>
                </div>
                <button
                  onClick={() => handleRevokeSession(session)}
                  disabled={session.status !== 'active' || busySessionId === session.id}
                  className="inline-flex items-center gap-2 rounded-xl border border-line px-3 py-2 text-sm font-medium text-ink-secondary transition-colors hover:bg-danger-soft hover:text-danger disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <IconLogOut size={14} />
                  {session.current ? '退出当前' : '下线'}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Future capabilities */}
      <div className="rounded-[20px] border border-line bg-surface-solid p-6 shadow-soft-sm">
        <div className="mb-4">
          <h2 className="text-lg font-semibold text-ink">更多安全能力</h2>
          <p className="mt-1 text-sm text-ink-tertiary">即将上线，敬请期待</p>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          {[
            { icon: IconFingerprint, name: 'Passkey', desc: '用指纹、面容或设备 PIN 登录' },
            { icon: IconKey, name: '备用验证', desc: '备用手机号或邮箱接收验证码' },
            { icon: IconBell, name: '安全通知', desc: '新设备登录、密码变更实时提醒' },
          ].map((item) => {
            const Icon = item.icon;
            return (
              <div key={item.name} className="rounded-2xl border border-dashed border-line bg-surface-muted p-5 opacity-60">
                <div className="flex items-center gap-2">
                  <Icon size={16} className="text-ink-tertiary" />
                  <span className="text-sm font-medium">{item.name}</span>
                  <span className="rounded-full bg-surface-hover px-2 py-0.5 text-[10px] font-medium text-ink-tertiary">即将上线</span>
                </div>
                <div className="mt-2 text-xs text-ink-tertiary">{item.desc}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Security suggestions */}
      <div className="rounded-[20px] border border-line bg-surface-solid p-6 shadow-soft-sm">
        <div className="mb-4">
          <h2 className="text-lg font-semibold text-ink">安全建议</h2>
          <p className="mt-1 text-sm text-ink-tertiary">为你整理的安全优化建议</p>
        </div>
        <div className="space-y-3">
          {visibleAlerts.map((a, i) => (
            <div key={i} className={`flex items-start gap-3 rounded-2xl border p-4 ${
              a.level === 'danger' ? 'border-danger/20 bg-danger-soft' : a.level === 'warning' ? 'border-warn/20 bg-warn-soft' : a.level === 'success' ? 'border-ok/20 bg-ok-soft' : 'border-brand/20 bg-brand-soft'
            }`}>
              <span className={`mt-0.5 ${a.level === 'danger' ? 'text-danger' : a.level === 'warning' ? 'text-warn' : a.level === 'success' ? 'text-ok' : 'text-brand'}`}>
                {a.level === 'success' ? <IconCheckCircle size={16} /> : <IconInfo size={16} />}
              </span>
              <div className="flex-1">
                <div className="text-sm font-medium">{a.title}</div>
                <div className="mt-1 text-xs leading-relaxed text-ink-secondary">{a.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Disable 2FA confirm modal */}
      <AccountModal open={confirmDisable} onClose={() => setConfirmDisable(false)}>
        <div>
          <div className="flex items-center gap-3">
            <div className="inline-flex h-10 w-10 items-center justify-center rounded-xl bg-danger-soft text-danger">
              <IconAlertTriangle size={18} />
            </div>
            <div>
              <div className="text-lg font-semibold">关闭两步验证？</div>
              <div className="text-sm text-ink-tertiary">关闭后账号安全等级会下降</div>
            </div>
          </div>
          <div className="mt-5 rounded-2xl border border-line bg-surface-muted p-4 text-sm leading-relaxed text-ink-secondary">
            关闭两步验证后，你的账号将仅依赖密码保护。如果密码被泄露，攻击者无需任何额外验证即可登录你的账号。强烈建议保持开启状态。
          </div>
          <div className="mt-6 flex justify-end gap-2">
            <button onClick={() => setConfirmDisable(false)} className="rounded-xl px-4 py-2.5 text-sm font-medium text-ink-secondary transition-colors hover:bg-surface-hover">
              保持开启
            </button>
            <button onClick={handleDisable} className="inline-flex items-center gap-2 rounded-xl bg-danger px-5 py-2.5 text-sm font-medium text-ink-inverse transition-colors hover:bg-danger-strong">
              <IconUnlink size={14} /> 确认关闭
            </button>
          </div>
        </div>
      </AccountModal>
    </div>
  );
}
