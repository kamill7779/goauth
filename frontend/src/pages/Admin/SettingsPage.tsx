import { useEffect, useState } from 'react'
import { getRuntimeConfig } from '../../api/admin'
import { getPublicConfig, normalizePublicConfig } from '../../api/publicConfig'
import type { RuntimeConfigPayload, RuntimeConfigStatus } from '../../types/admin'
import type { PublicAuthConfig } from '../../types/publicConfig'

export interface RuntimeStatusItem {
  label: string
  value: string
  description: string
  readOnly: true
}

export interface RuntimeStatusGroup {
  section: string
  items: RuntimeStatusItem[]
}

export interface RuntimeDiagnosticItem {
  label: string
  value: string
  description: string
  severity: RuntimeConfigStatus
  readOnly: true
}

export interface RuntimeDiagnosticGroup {
  section: string
  items: RuntimeDiagnosticItem[]
}

export function buildRuntimeStatusGroups(configLike: unknown): RuntimeStatusGroup[] {
  const config = normalizePublicConfig(configLike)
  const githubEnabled = config.external_providers.some(provider => provider.slug === 'github')

  return [
    {
      section: '认证入口',
      items: [
        {
          label: '注册模式',
          value: registrationModeLabel(config.registration.mode),
          description: '来自 REGISTRATION_MODE',
          readOnly: true,
        },
        {
          label: '本地密码登录',
          value: config.local_login.enabled ? '启用' : '关闭',
          description: '来自 LOCAL_PASSWORD_LOGIN_ENABLED',
          readOnly: true,
        },
        {
          label: 'GitHub 登录',
          value: githubEnabled ? '启用' : '关闭',
          description: '来自 GITHUB_OAUTH_ENABLED 和 GitHub OAuth 客户端配置',
          readOnly: true,
        },
      ],
    },
    {
      section: '验证与邮件',
      items: [
        {
          label: 'CAPTCHA',
          value: captchaLabel(config),
          description: '来自 CAPTCHA_PROVIDER、CAPTCHA_SITE_KEY 和 CAPTCHA_ACTIONS',
          readOnly: true,
        },
        {
          label: '邮件发送',
          value: config.mailer.provider,
          description: '来自 MAILER_PROVIDER',
          readOnly: true,
        },
      ],
    },
    {
      section: '密码策略',
      items: [
        {
          label: '最小长度',
          value: `${config.password_policy.min_length}`,
          description: '来自 PASSWORD_MIN_LENGTH',
          readOnly: true,
        },
        {
          label: '复杂度要求',
          value: passwordPolicyLabel(config),
          description: '来自 PASSWORD_REQUIRE_*',
          readOnly: true,
        },
      ],
    },
  ]
}

export function runtimeStatusGroupsForLoadedConfig(config: PublicAuthConfig | null): RuntimeStatusGroup[] {
  return config ? buildRuntimeStatusGroups(config) : []
}

export function buildRuntimeDiagnosticGroups(runtimeConfig: RuntimeConfigPayload | null): RuntimeDiagnosticGroup[] {
  if (!runtimeConfig) {
    return []
  }
  return runtimeConfig.groups.map(group => ({
    section: group.key,
    items: group.items.map(item => ({
      label: item.key,
      value: runtimeStatusLabel(item.status),
      severity: item.status,
      description: runtimeDiagnosticDescription(item),
      readOnly: true,
    })),
  }))
}

function registrationModeLabel(mode: PublicAuthConfig['registration']['mode']): string {
  if (mode === 'invite_only') {
    return '仅邀请'
  }
  if (mode === 'disabled') {
    return '关闭'
  }
  return '开放'
}

function captchaLabel(config: PublicAuthConfig): string {
  if (!config.captcha.provider) {
    return '关闭'
  }
  const actions = config.captcha.actions.length > 0 ? `: ${config.captcha.actions.join(', ')}` : ''
  return `${config.captcha.provider}${actions}`
}

function passwordPolicyLabel(config: PublicAuthConfig): string {
  const requirements = [
    config.password_policy.require_uppercase ? '大写' : '',
    config.password_policy.require_lowercase ? '小写' : '',
    config.password_policy.require_digit ? '数字' : '',
    config.password_policy.require_special ? '特殊字符' : '',
  ].filter(Boolean)
  return requirements.length > 0 ? requirements.join('、') : '无额外复杂度要求'
}

function runtimeStatusLabel(status: RuntimeConfigStatus): string {
  if (status === 'error') {
    return '错误'
  }
  if (status === 'warning') {
    return '警告'
  }
  return '正常'
}

function runtimeDiagnosticDescription(item: RuntimeConfigPayload['groups'][number]['items'][number]): string {
  const flags = [
    item.required ? '生产必填' : '可选',
    item.secret ? '敏感' : '非敏感',
    item.public_config ? '公开配置可见' : '不在公开配置中',
    item.configured ? '已配置' : '未配置',
  ]
  return `${item.message || item.source} · ${flags.join(' · ')}`
}

function severityClass(status: RuntimeConfigStatus): string {
  if (status === 'error') {
    return 'border-red-200 bg-red-50 text-red-700'
  }
  if (status === 'warning') {
    return 'border-amber-200 bg-amber-50 text-amber-700'
  }
  return 'border-line bg-surface-muted text-ink'
}

export default function SettingsPage() {
  const [config, setConfig] = useState<PublicAuthConfig | null>(null)
  const [runtimeConfig, setRuntimeConfig] = useState<RuntimeConfigPayload | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    Promise.allSettled([getPublicConfig(), getRuntimeConfig()])
      .then(([publicResult, runtimeResult]) => {
        if (cancelled) {
          return
        }
        const errors: string[] = []
        if (publicResult.status === 'fulfilled') {
          setConfig(publicResult.value)
        } else {
          errors.push(publicResult.reason instanceof Error ? publicResult.reason.message : '读取公开运行配置失败')
        }
        if (runtimeResult.status === 'fulfilled') {
          setRuntimeConfig(runtimeResult.value)
        } else {
          errors.push(runtimeResult.reason instanceof Error ? runtimeResult.reason.message : '读取后台运行诊断失败')
        }
        setError(errors.join('；'))
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false)
        }
      })
    return () => {
      cancelled = true
    }
  }, [])

  const groups = runtimeStatusGroupsForLoadedConfig(config)
  const diagnosticGroups = buildRuntimeDiagnosticGroups(runtimeConfig)

  return (
    <div className="animate-[fadeInUp_0.4s_ease]">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-ink mb-1">系统设置</h1>
        <p className="text-sm text-ink-tertiary">当前运行配置只读展示，修改请更新环境变量并重启服务</p>
      </div>

      {error && (
        <div className="max-w-2xl mb-5 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(360px,0.9fr)]">
        <div className="space-y-6">
        {loading && (
          <div className="bg-surface-solid rounded-xl border border-line px-5 py-4 text-sm text-ink-tertiary">
            正在读取运行配置...
          </div>
        )}
        {!loading && !error && groups.map(group => (
          <div key={group.section} className="bg-surface-solid rounded-[20px] border border-line overflow-hidden">
            <div className="px-5 py-3.5 border-b border-line bg-surface-muted flex items-center justify-between">
              <h2 className="text-sm font-semibold text-ink">{group.section}</h2>
              <span className="text-[11px] font-medium text-ink-tertiary">{loading ? '读取中' : '只读'}</span>
            </div>
            <div className="divide-y divide-line">
              {group.items.map(item => (
                <div key={item.label} className="px-5 py-4 flex items-center justify-between gap-5">
                  <div>
                    <p className="text-sm font-medium text-ink">{item.label}</p>
                    <p className="text-xs text-ink-tertiary mt-0.5">{item.description}</p>
                  </div>
                  <div className="shrink-0 text-right">
                    <span className="inline-flex max-w-[220px] items-center justify-center rounded-lg border border-line bg-surface-muted px-3 py-1.5 text-xs font-medium text-ink">
                      {item.value}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
        </div>

        <div className="space-y-6">
          {!loading && runtimeConfig && (
            <div className="bg-surface-solid rounded-[20px] border border-line overflow-hidden">
              <div className="px-5 py-3.5 border-b border-line bg-surface-muted flex items-center justify-between">
                <h2 className="text-sm font-semibold text-ink">运行诊断</h2>
                <span className="text-[11px] font-medium text-ink-tertiary">{runtimeConfig.environment}</span>
              </div>
              <div className="divide-y divide-line">
                {diagnosticGroups.flatMap(group => group.items).map(item => (
                  <div key={item.label} className="px-5 py-4 flex items-start justify-between gap-4">
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-ink break-all">{item.label}</p>
                      <p className="text-xs text-ink-tertiary mt-1 leading-5">{item.description}</p>
                    </div>
                    <span className={`shrink-0 inline-flex items-center rounded-lg border px-2.5 py-1 text-xs font-medium ${severityClass(item.severity)}`}>
                      {item.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
