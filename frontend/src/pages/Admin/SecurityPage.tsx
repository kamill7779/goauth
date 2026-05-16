import { IconMail } from '../../components/admin/Icons';

export default function SecurityPage() {
  return (
    <div className="animate-[fadeInUp_0.4s_ease]">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-ink mb-1">邮件与安全</h1>
        <p className="text-sm text-ink-tertiary">配置邮件服务、安全通知和告警规则</p>
      </div>
      <div className="bg-surface-solid rounded-[20px] border border-line p-12 text-center">
        <IconMail size={32} className="text-ink-muted mx-auto mb-4" />
        <h3 className="text-sm font-medium text-ink-secondary mb-1">邮件配置</h3>
        <p className="text-xs text-ink-tertiary max-w-sm mx-auto">
          配置 SMTP 服务器以启用邮件通知、密码重置和验证邮件功能。
        </p>
      </div>
    </div>
  );
}
