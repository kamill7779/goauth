import { useState, useCallback, useEffect, FormEvent } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { forgotPassword, login, register, resetPassword, sendEmailCode } from '../api/auth'
import { API_BASE_URL } from '../api/client'
import { captchaEnabledForAction, defaultPublicConfig, getPublicConfig, normalizePublicConfig } from '../api/publicConfig'
import ThemeToggle from '../components/admin/ThemeToggle'
import BrandMark from '../components/BrandMark'
import TurnstileCaptcha from '../components/auth/TurnstileCaptcha'
import type { PublicAuthConfig } from '../types/publicConfig'

interface FormData {
  identifier: string
  email: string
  password: string
  username: string
  nickname: string
  emailCode: string
}

const initialForm: FormData = {
  identifier: '',
  email: '',
  password: '',
  username: '',
  nickname: '',
  emailCode: '',
}

type CaptchaAction = 'login' | 'register' | 'email_code' | 'password_forgot'

type CaptchaBridge = {
  getToken?: (context: { action: CaptchaAction }) => Promise<string | null | undefined> | string | null | undefined
}

type AuthorizeReturnOptions = {
  currentOrigin?: string
  apiBaseURL?: string
  issuerURL?: string
}

type AuthEntryVisibility = ReturnType<typeof authEntryVisibility>

declare global {
  interface Window {
    __goauthCaptcha?: CaptchaBridge
  }
}

const OIDC_ISSUER_URL = import.meta.env?.VITE_OIDC_ISSUER_URL?.trim() ?? ''

function originFromURL(raw: string, fallback: string): string | null {
  try {
    return new URL(raw, fallback).origin
  } catch {
    return null
  }
}

export function normalizeAuthorizeReturnTo(raw: string, options?: AuthorizeReturnOptions): string {
  const returnTo = raw.trim()
  if (!returnTo) {
    return ''
  }

  const currentOrigin = options?.currentOrigin?.trim() || (typeof window !== 'undefined' ? window.location.origin : 'http://localhost:8080')
  const apiBaseURL = options?.apiBaseURL?.trim() || API_BASE_URL
  const issuerURL = options?.issuerURL?.trim() || OIDC_ISSUER_URL
  const currentAppOrigin = originFromURL(currentOrigin, 'http://localhost:8080')
  const apiOrigin = originFromURL(apiBaseURL, currentOrigin)
  const issuerOrigin = issuerURL ? originFromURL(issuerURL, currentOrigin) : null

  if (!currentAppOrigin && !issuerOrigin && !apiOrigin) {
    return ''
  }

  try {
    const parsed = new URL(returnTo, currentOrigin)
    if (parsed.pathname !== '/oauth2/authorize') {
      return ''
    }
    const trustedExternalOrigin = issuerOrigin || apiOrigin
    if (parsed.origin !== currentAppOrigin && parsed.origin !== trustedExternalOrigin) {
      return ''
    }
    if (parsed.origin === currentAppOrigin) {
      if (trustedExternalOrigin && parsed.origin !== trustedExternalOrigin && issuerOrigin) {
        return ''
      }
      return parsed.pathname + parsed.search
    }
    return parsed.toString()
  } catch {
    return ''
  }
}

function getAuthorizeReturnTo(search: string, issuerURL?: string): string {
  return normalizeAuthorizeReturnTo(new URLSearchParams(search).get('return_to')?.trim() ?? '', {
    currentOrigin: window.location.origin,
    apiBaseURL: API_BASE_URL,
    issuerURL: issuerURL || OIDC_ISSUER_URL,
  })
}

export function authEntryVisibility(configLike: unknown) {
  const config = normalizePublicConfig(configLike)
  return {
    showRegister: config.registration.mode === 'open',
    showLocalLogin: config.local_login.enabled,
    githubProvider: config.external_providers.find(provider => provider.slug === 'github') ?? null,
  }
}

export function buildExternalProviderStartURL(
  provider: PublicAuthConfig['external_providers'][number],
  returnTo: string,
  apiBaseURL = API_BASE_URL,
): string {
  const url = new URL(provider.start_url, apiBaseURL)
  const normalizedReturnTo = normalizeExternalProviderReturnTo(returnTo, url)
  if (normalizedReturnTo) {
    url.searchParams.set('return_to', normalizedReturnTo)
  }
  return url.toString()
}

function normalizeExternalProviderReturnTo(returnTo: string, providerStartURL: URL): string {
  void providerStartURL
  return returnTo.trim()
}

export function buildAuthConfigViewState(config: PublicAuthConfig | null, loading: boolean, error: string): {
  visibility: AuthEntryVisibility
  canUseAuthActions: boolean
  statusMessage: string
} {
  const emptyVisibility: AuthEntryVisibility = {
    showRegister: false,
    showLocalLogin: false,
    githubProvider: null,
  }
  return {
    visibility: config ? authEntryVisibility(config) : emptyVisibility,
    canUseAuthActions: Boolean(config) && !loading && !error,
    statusMessage: loading ? '正在读取认证配置...' : error ? '认证配置不可用，请稍后重试' : '',
  }
}

async function getCaptchaToken(config: PublicAuthConfig, action: CaptchaAction): Promise<string | undefined> {
  if (!captchaEnabledForAction(config, action)) {
    return undefined
  }

  const token = await window.__goauthCaptcha?.getToken?.({ action })
  const normalized = token?.trim() ?? ''
  if (!normalized) {
    throw new Error('CAPTCHA 已启用，但当前页面未提供有效的验证码令牌')
  }
  return normalized
}

export function buildAuthRoutePath(
  pathname: string,
  options?: { email?: string; returnTo?: string },
): string {
  const params = new URLSearchParams()
  const email = options?.email?.trim() ?? ''
  const returnTo = options?.returnTo?.trim() ?? ''

  if (email) {
    params.set('email', email)
  }
  if (returnTo) {
    params.set('return_to', returnTo)
  }

  const query = params.toString()
  return query ? `${pathname}?${query}` : pathname
}

export function resolvePostLoginRedirect(returnTo: string): { mode: 'app' | 'external'; target: string } {
  const target = returnTo.trim()
  if (target) {
    return { mode: 'external', target }
  }
  return { mode: 'app', target: '/account' }
}

function Spinner() {
  return (
    <span
      style={{
        display: 'inline-block',
        width: '16px',
        height: '16px',
        border: '2px solid rgba(255,255,255,0.3)',
        borderTopColor: '#fff',
        borderRadius: '50%',
        animation: 'spin 0.6s linear infinite',
      }}
    />
  )
}

export default function LoginPage() {
  const location = useLocation()
  const navigate = useNavigate()
  const pageMode = location.pathname === '/forgot-password'
    ? 'forgot'
    : location.pathname === '/reset-password'
      ? 'reset'
      : 'auth'
  const routeState = location.state as { notice?: string } | null
  const emailFromQuery = new URLSearchParams(location.search).get('email')?.trim() ?? ''

  const [tab, setTab] = useState<'login' | 'register'>('login')
  const [form, setForm] = useState<FormData>(initialForm)
  const [loading, setLoading] = useState(false)
  const [codeSending, setCodeSending] = useState(false)
  const [codeCountdown, setCodeCountdown] = useState(0)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [authConfig, setAuthConfig] = useState<PublicAuthConfig | null>(null)
  const [configLoading, setConfigLoading] = useState(true)
  const [configError, setConfigError] = useState('')

  const authConfigState = buildAuthConfigViewState(authConfig, configLoading, configError)
  const visibility = authConfigState.visibility
  const githubProvider = visibility.githubProvider
  const brand = authConfig?.brand ?? defaultPublicConfig.brand
  const returnTo = getAuthorizeReturnTo(location.search, authConfig?.issuer_url)
  const isSSOLogin = returnTo !== ''

  useEffect(() => {
    let cancelled = false
    getPublicConfig()
      .then(config => {
        if (!cancelled) {
          setAuthConfig(config)
          setConfigError('')
        }
      })
      .catch(err => {
        if (!cancelled) {
          setAuthConfig(null)
          setConfigError(err instanceof Error ? err.message : '读取认证配置失败')
        }
      })
      .finally(() => {
        if (!cancelled) {
          setConfigLoading(false)
        }
      })
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    if (routeState?.notice) {
      setSuccess(routeState.notice)
    }
  }, [routeState?.notice])

  useEffect(() => {
    if (!emailFromQuery) {
      return
    }
    setForm(prev => (prev.email ? prev : { ...prev, email: emailFromQuery }))
  }, [emailFromQuery])

  useEffect(() => {
    if (tab === 'register' && !visibility.showRegister) {
      setTab('login')
    }
    if (tab === 'login' && !visibility.showLocalLogin && visibility.showRegister) {
      setTab('register')
    }
  }, [tab, visibility.showLocalLogin, visibility.showRegister])

  useEffect(() => {
    if (codeCountdown <= 0) {
      return
    }
    const timer = window.setTimeout(() => {
      setCodeCountdown(prev => prev - 1)
    }, 1000)
    return () => window.clearTimeout(timer)
  }, [codeCountdown])

  const updateField = useCallback((field: keyof FormData, value: string) => {
    setForm(prev => ({ ...prev, [field]: value }))
    setError('')
  }, [])

  const sendRegisterCode = useCallback(async () => {
    if (!authConfig) {
      setError('认证运行配置不可用，请稍后重试')
      return
    }
    if (!form.email) {
      setError('请先输入邮箱地址')
      return
    }
    setCodeSending(true)
    setError('')
    try {
      const captchaToken = await getCaptchaToken(authConfig, 'email_code')
      await sendEmailCode({ purpose: 'register', email: form.email }, { captchaToken })
      setSuccess('验证码已发送')
      setCodeCountdown(60)
    } catch (err) {
      setError(err instanceof Error ? err.message : '发送失败')
    } finally {
      setCodeSending(false)
    }
  }, [authConfig, form.email])

  const sendResetCode = useCallback(async () => {
    if (!authConfig) {
      setError('认证运行配置不可用，请稍后重试')
      return
    }
    if (!form.email) {
      setError('请先输入邮箱地址')
      return
    }
    setCodeSending(true)
    setError('')
    try {
      const captchaToken = await getCaptchaToken(authConfig, 'password_forgot')
      await forgotPassword(form.email, { captchaToken })
      setSuccess('重置验证码已发送，请查收邮箱')
      setCodeCountdown(60)
    } catch (err) {
      setError(err instanceof Error ? err.message : '发送失败')
    } finally {
      setCodeSending(false)
    }
  }, [authConfig, form.email])

  const handleLoginSubmit = useCallback(async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    if (!authConfig) {
      setError('认证运行配置不可用，请稍后重试')
      return
    }
    setLoading(true)
    setError('')
    setSuccess('')

    try {
      const captchaToken = await getCaptchaToken(authConfig, 'login')
      const result = await login({ identifier: form.identifier || form.email, password: form.password }, { captchaToken })
      window.localStorage.setItem('access_token', result.access_token)
      window.localStorage.setItem('refresh_token', result.refresh_token)
      const redirect = resolvePostLoginRedirect(returnTo)
      if (redirect.mode === 'external') {
        window.location.assign(redirect.target)
        return
      }
      navigate(redirect.target)
    } catch (err) {
      setError(err instanceof Error ? err.message : '操作失败')
    } finally {
      setLoading(false)
    }
  }, [authConfig, form.identifier, form.email, form.password, navigate, returnTo])

  const handleRegisterSubmit = useCallback(async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    if (!authConfig) {
      setError('认证运行配置不可用，请稍后重试')
      return
    }
    setLoading(true)
    setError('')
    setSuccess('')

    try {
      const captchaToken = await getCaptchaToken(authConfig, 'register')
      await register({
        username: form.username,
        nickname: form.nickname,
        email: form.email,
        password: form.password,
        email_code: form.emailCode,
      }, { captchaToken })
      setSuccess(isSSOLogin ? '注册成功，请使用新账户登录后继续' : '注册成功，请登录')
      setTab('login')
      setForm(prev => ({ ...initialForm, email: prev.email }))
    } catch (err) {
      setError(err instanceof Error ? err.message : '操作失败')
    } finally {
      setLoading(false)
    }
  }, [authConfig, form, isSSOLogin])

  const handleForgotSubmit = useCallback(async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    if (!authConfig) {
      setError('认证运行配置不可用，请稍后重试')
      return
    }
    setLoading(true)
    setError('')
    setSuccess('')

    try {
      const captchaToken = await getCaptchaToken(authConfig, 'password_forgot')
      await forgotPassword(form.email, { captchaToken })
      navigate(buildAuthRoutePath('/reset-password', { email: form.email, returnTo }), {
        state: { notice: '重置验证码已发送，请输入邮箱验证码并设置新密码' },
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : '操作失败')
    } finally {
      setLoading(false)
    }
  }, [authConfig, form.email, navigate, returnTo])

  const handleResetSubmit = useCallback(async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    if (!authConfig) {
      setError('认证运行配置不可用，请稍后重试')
      return
    }
    setLoading(true)
    setError('')
    setSuccess('')

    try {
      await resetPassword({
        email: form.email,
        email_code: form.emailCode,
        new_password: form.password,
      })
      setForm({ ...initialForm, email: form.email })
      navigate(buildAuthRoutePath('/login', { returnTo }), {
        replace: true,
        state: { notice: '密码已重置，请使用新密码登录' },
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : '操作失败')
    } finally {
      setLoading(false)
    }
  }, [form.email, form.emailCode, form.password, navigate, returnTo])

  const handleGitHubLogin = useCallback(() => {
    if (!githubProvider) {
      return
    }
    window.location.assign(buildExternalProviderStartURL(githubProvider, returnTo))
  }, [githubProvider, returnTo])

  const switchTab = useCallback((nextTab: 'login' | 'register') => {
    setTab(nextTab)
    setError('')
    setSuccess('')
    setForm({ ...initialForm, email: form.email })
  }, [form.email])

  const cardStyle: React.CSSProperties = {
    width: '100%',
    maxWidth: '420px',
    background: 'var(--surface-solid)',
    backdropFilter: 'blur(24px) saturate(1.8)',
    WebkitBackdropFilter: 'blur(24px) saturate(1.8)',
    border: '1px solid var(--border)',
    borderRadius: '24px',
    boxShadow: 'var(--shadow-md)',
    padding: '52px 44px',
    position: 'relative',
    overflow: 'hidden',
    animation: 'cardEnter 0.7s cubic-bezier(0.16, 1, 0.3, 1) 0.1s forwards',
    opacity: 0,
  }

  const segmentedStyle: React.CSSProperties = {
    display: 'flex',
    background: 'var(--surface-hover)',
    borderRadius: '10px',
    padding: '3px',
    marginBottom: '32px',
    position: 'relative',
  }

  const segmentBtnStyle = (active: boolean): React.CSSProperties => ({
    flex: 1,
    background: 'none',
    border: 'none',
    fontFamily: 'inherit',
    fontSize: '14px',
    fontWeight: 500,
    color: active ? 'var(--ink)' : 'var(--ink-secondary)',
    padding: '10px 16px',
    cursor: 'pointer',
    borderRadius: '8px',
    position: 'relative',
    zIndex: 1,
    transition: 'color 0.25s ease',
  })

  const indicatorStyle: React.CSSProperties = {
    position: 'absolute',
    top: '3px',
    bottom: '3px',
    width: 'calc(50% - 3px)',
    background: 'var(--surface-solid)',
    borderRadius: '10px',
    boxShadow: 'var(--shadow-sm)',
    transition: 'transform 0.35s cubic-bezier(0.34, 1.56, 0.64, 1)',
    zIndex: 0,
    transform: tab === 'register' ? 'translateX(calc(100% + 6px))' : 'translateX(0)',
  }

  const inputStyle: React.CSSProperties = {
    width: '100%',
    padding: '14px 18px',
    fontFamily: 'inherit',
    fontSize: '15px',
    color: 'var(--ink)',
    background: 'var(--surface-solid)',
    border: '1.5px solid var(--border-strong)',
    borderRadius: '14px',
    outline: 'none',
    transition: 'border-color 0.2s ease, box-shadow 0.2s ease',
  }

  const btnPrimaryStyle = (disabled: boolean): React.CSSProperties => ({
    width: '100%',
    padding: '15px 24px',
    fontFamily: 'inherit',
    fontSize: '15px',
    fontWeight: 500,
    color: '#fff',
    background: disabled ? 'var(--ink-tertiary)' : 'var(--accent)',
    border: 'none',
    borderRadius: '14px',
    cursor: disabled ? 'not-allowed' : 'pointer',
    transition: 'background 0.2s ease, transform 0.1s ease, box-shadow 0.2s ease',
    boxShadow: '0 2px 8px var(--accent-glow)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
  })

  const btnSecondaryStyle: React.CSSProperties = {
    width: '100%',
    padding: '14px 20px',
    fontFamily: 'inherit',
    fontSize: '15px',
    fontWeight: 500,
    color: 'var(--ink)',
    background: 'var(--surface-solid)',
    border: '1.5px solid var(--border-strong)',
    borderRadius: '14px',
    cursor: 'pointer',
    transition: 'border-color 0.2s ease, background 0.2s ease, transform 0.1s ease',
  }

  const headerTitle = pageMode === 'forgot'
    ? '找回密码'
    : pageMode === 'reset'
      ? '重置密码'
      : tab === 'login'
        ? '欢迎回来'
        : '创建账户'

  const headerDescription = pageMode === 'forgot'
    ? '输入账户邮箱，我们会向你发送密码重置验证码'
    : pageMode === 'reset'
      ? '输入邮箱验证码并设置新密码'
      : tab === 'login'
        ? isSSOLogin
          ? `登录你的 ${brand.name} 账户以继续访问当前服务`
          : `登录你的 ${brand.name} 账户`
        : '开始你的安全身份之旅'

  const authActionDisabled = loading || !authConfigState.canUseAuthActions

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '40px 24px',
        position: 'relative',
        background: 'var(--bg)',
      }}
    >
      <div
        style={{
          position: 'fixed',
          top: '-30%',
          right: '-20%',
          width: '700px',
          height: '700px',
          borderRadius: '50%',
          background: 'radial-gradient(circle, var(--cream-glow) 0%, transparent 70%)',
          pointerEvents: 'none',
          zIndex: -1,
        }}
      />
      <div
        style={{
          position: 'fixed',
          bottom: '-25%',
          left: '-15%',
          width: '500px',
          height: '500px',
          borderRadius: '50%',
          background: 'radial-gradient(circle, var(--accent-soft) 0%, transparent 70%)',
          pointerEvents: 'none',
          zIndex: -1,
        }}
      />

      <div style={{ position: 'fixed', top: 24, right: 24, zIndex: 10 }}>
        <ThemeToggle variant="inline" />
      </div>

      <div style={cardStyle}>
        <div
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            height: '1px',
            background: 'linear-gradient(90deg, transparent, var(--border-strong), transparent)',
          }}
        />

        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <BrandMark brand={brand} size="lg" orientation="stacked" align="center" showTagline />
        </div>

        <div style={{ textAlign: 'center', marginBottom: '36px' }}>
          <h1 style={{ fontSize: '24px', fontWeight: 600, marginBottom: '8px', letterSpacing: '-0.3px', color: 'var(--ink)' }}>
            {headerTitle}
          </h1>
          <p style={{ fontSize: '14px', color: 'var(--ink-secondary)', lineHeight: 1.5 }}>
            {headerDescription}
          </p>
        </div>

        {pageMode === 'auth' && visibility.showLocalLogin && visibility.showRegister && (
          <div style={segmentedStyle}>
            <div style={indicatorStyle} />
            <button
              type="button"
              style={segmentBtnStyle(tab === 'login')}
              onClick={() => switchTab('login')}
            >
              登录
            </button>
            <button
              type="button"
              style={segmentBtnStyle(tab === 'register')}
              onClick={() => switchTab('register')}
            >
              注册
            </button>
          </div>
        )}

        {error && (
          <div
            style={{
              marginBottom: '20px',
              padding: '12px 14px',
              borderRadius: '10px',
              background: 'var(--error-soft)',
              color: 'var(--error)',
              fontSize: '14px',
              lineHeight: 1.5,
            }}
          >
            {error}
          </div>
        )}
        {success && (
          <div
            style={{
              marginBottom: '20px',
              padding: '12px 14px',
              borderRadius: '10px',
              background: 'var(--success-soft)',
              color: 'var(--success)',
              fontSize: '14px',
              lineHeight: 1.5,
            }}
          >
            {success}
          </div>
        )}
        {authConfigState.statusMessage && (
          <div
            style={{
              marginBottom: '20px',
              padding: '12px 14px',
              borderRadius: '10px',
              background: 'var(--surface-hover)',
              color: 'var(--ink-secondary)',
              fontSize: '14px',
              lineHeight: 1.5,
            }}
          >
            {authConfigState.statusMessage}
          </div>
        )}

        {pageMode === 'auth' && (
          <>
            <form
              onSubmit={handleLoginSubmit}
              style={{ display: visibility.showLocalLogin && tab === 'login' ? 'block' : 'none', animation: tab === 'login' ? 'fadeIn 0.35s ease' : 'none' }}
            >
              <div style={{ marginBottom: '18px' }}>
                <label htmlFor="login-identifier" style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--ink-secondary)', marginBottom: '7px', paddingLeft: '2px' }}>
                  用户名或邮箱
                </label>
                <input
                  id="login-identifier"
                  name="identifier"
                  type="text"
                  value={form.identifier}
                  onChange={e => updateField('identifier', e.target.value)}
                  placeholder="用户名或 name@company.com"
                  autoComplete="username"
                  required
                  style={inputStyle}
                />
              </div>

              <div style={{ marginBottom: '18px' }}>
                <label htmlFor="login-password" style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--ink-secondary)', marginBottom: '7px', paddingLeft: '2px' }}>
                  密码
                </label>
                <input
                  id="login-password"
                  name="password"
                  type="password"
                  value={form.password}
                  onChange={e => updateField('password', e.target.value)}
                  placeholder="输入密码"
                  autoComplete="current-password"
                  required
                  style={inputStyle}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', margin: '8px 0 24px' }}>
                <label htmlFor="remember-me" style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '13px', color: 'var(--ink-secondary)' }}>
                  <input id="remember-me" name="remember_me" type="checkbox" style={{ width: '18px', height: '18px', accentColor: 'var(--accent)' }} />
                  <span>记住我</span>
                </label>
                <Link to={buildAuthRoutePath('/forgot-password', { returnTo })} style={{ fontSize: '13px', color: 'var(--accent)', textDecoration: 'none', fontWeight: 500 }}>
                  忘记密码？
                </Link>
              </div>

              <button type="submit" disabled={authActionDisabled} style={btnPrimaryStyle(authActionDisabled)}>
                {loading ? <><Spinner /> 登录中...</> : isSSOLogin ? '继续' : '登录'}
              </button>
            </form>

            <form onSubmit={handleRegisterSubmit} style={{ display: visibility.showRegister && tab === 'register' ? 'block' : 'none', animation: tab === 'register' ? 'fadeIn 0.35s ease' : 'none' }}>
              <div style={{ marginBottom: '18px' }}>
                <label htmlFor="register-username" style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--ink-secondary)', marginBottom: '7px', paddingLeft: '2px' }}>
                  用户名
                </label>
                <input
                  id="register-username"
                  name="username"
                  type="text"
                  value={form.username}
                  onChange={e => updateField('username', e.target.value)}
                  placeholder="3-32 位字母、数字、下划线或连字符"
                  autoComplete="username"
                  required
                  style={inputStyle}
                />
              </div>

              <div style={{ marginBottom: '18px' }}>
                <label htmlFor="register-nickname" style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--ink-secondary)', marginBottom: '7px', paddingLeft: '2px' }}>
                  昵称
                </label>
                <input
                  id="register-nickname"
                  name="nickname"
                  type="text"
                  value={form.nickname}
                  onChange={e => updateField('nickname', e.target.value)}
                  placeholder="选填，用于展示"
                  style={inputStyle}
                />
              </div>

              <div style={{ marginBottom: '18px' }}>
                <label htmlFor="register-email" style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--ink-secondary)', marginBottom: '7px', paddingLeft: '2px' }}>
                  邮箱地址
                </label>
                <input
                  id="register-email"
                  name="email"
                  type="email"
                  value={form.email}
                  onChange={e => updateField('email', e.target.value)}
                  placeholder="name@company.com"
                  autoComplete="email"
                  required
                  style={inputStyle}
                />
              </div>

              <div style={{ marginBottom: '18px' }}>
                <label htmlFor="register-password" style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--ink-secondary)', marginBottom: '7px', paddingLeft: '2px' }}>
                  密码
                </label>
                <input
                  id="register-password"
                  name="password"
                  type="password"
                  value={form.password}
                  onChange={e => updateField('password', e.target.value)}
                  placeholder="至少 8 位字符"
                  autoComplete="new-password"
                  required
                  style={inputStyle}
                />
              </div>

              <div style={{ marginBottom: '18px' }}>
                <label htmlFor="register-email-code" style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--ink-secondary)', marginBottom: '7px', paddingLeft: '2px' }}>
                  邮箱验证码
                </label>
                <div style={{ display: 'flex', gap: '12px' }}>
                  <input
                    id="register-email-code"
                    name="email_code"
                    type="text"
                    value={form.emailCode}
                    onChange={e => updateField('emailCode', e.target.value)}
                    placeholder="6 位验证码"
                    required
                    style={{ ...inputStyle, flex: 1 }}
                  />
                  <button
                    type="button"
                    disabled={codeSending || codeCountdown > 0 || !authConfigState.canUseAuthActions}
                    onClick={sendRegisterCode}
                    style={{
                      padding: '13px 20px',
                      fontSize: '13px',
                      fontWeight: 500,
                      color: codeCountdown > 0 ? 'var(--ink-secondary)' : 'var(--ink-inverse)',
                      background: codeCountdown > 0 ? 'var(--surface-hover)' : 'var(--ink)',
                      border: '1px solid ' + (codeCountdown > 0 ? 'var(--border)' : 'transparent'),
                      borderRadius: '10px',
                      cursor: codeSending || codeCountdown > 0 || !authConfigState.canUseAuthActions ? 'not-allowed' : 'pointer',
                      transition: 'background 0.2s ease',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {codeSending ? <Spinner /> : codeCountdown > 0 ? `${codeCountdown}s` : '发送验证码'}
                  </button>
                </div>
              </div>

              <button type="submit" disabled={authActionDisabled} style={btnPrimaryStyle(authActionDisabled)}>
                {loading ? <><Spinner /> 创建中...</> : '创建账户'}
              </button>
            </form>

            {githubProvider && (
              <div style={{ marginTop: visibility.showLocalLogin || visibility.showRegister ? '24px' : 0 }}>
                {(visibility.showLocalLogin || visibility.showRegister) && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', margin: '0 0 20px' }}>
                    <span style={{ flex: 1, height: '1px', background: 'var(--border)' }} />
                    <span style={{ fontSize: '12px', color: 'var(--ink-tertiary)' }}>或</span>
                    <span style={{ flex: 1, height: '1px', background: 'var(--border)' }} />
                  </div>
                )}
                <button type="button" onClick={handleGitHubLogin} disabled={!authConfigState.canUseAuthActions} style={btnSecondaryStyle}>
                  使用 {githubProvider.display_name} 继续
                </button>
              </div>
            )}

            {!visibility.showLocalLogin && !visibility.showRegister && !githubProvider && !authConfigState.statusMessage && (
              <div style={{ fontSize: '14px', color: 'var(--ink-secondary)', lineHeight: 1.6, textAlign: 'center' }}>
                当前没有可用的登录方式
              </div>
            )}
          </>
        )}

        {pageMode === 'forgot' && (
          <form onSubmit={handleForgotSubmit}>
            <div style={{ marginBottom: '18px' }}>
              <label htmlFor="forgot-email" style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--ink-secondary)', marginBottom: '7px', paddingLeft: '2px' }}>
                邮箱地址
              </label>
              <input
                id="forgot-email"
                name="email"
                type="email"
                value={form.email}
                onChange={e => updateField('email', e.target.value)}
                placeholder="name@company.com"
                autoComplete="email"
                required
                style={inputStyle}
              />
            </div>

            <button type="submit" disabled={authActionDisabled} style={btnPrimaryStyle(authActionDisabled)}>
              {loading ? <><Spinner /> 发送中...</> : '发送重置验证码'}
            </button>

            <div style={{ marginTop: '18px', textAlign: 'center' }}>
              <Link to={buildAuthRoutePath('/login', { returnTo })} style={{ fontSize: '13px', color: 'var(--accent)', textDecoration: 'none', fontWeight: 500 }}>
                返回登录
              </Link>
            </div>
          </form>
        )}

        {pageMode === 'reset' && (
          <form onSubmit={handleResetSubmit}>
            <div style={{ marginBottom: '18px' }}>
              <label htmlFor="reset-email" style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--ink-secondary)', marginBottom: '7px', paddingLeft: '2px' }}>
                邮箱地址
              </label>
              <input
                id="reset-email"
                name="email"
                type="email"
                value={form.email}
                onChange={e => updateField('email', e.target.value)}
                placeholder="name@company.com"
                autoComplete="email"
                required
                style={inputStyle}
              />
            </div>

            <div style={{ marginBottom: '18px' }}>
              <label htmlFor="reset-password" style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--ink-secondary)', marginBottom: '7px', paddingLeft: '2px' }}>
                新密码
              </label>
              <input
                id="reset-password"
                name="new_password"
                type="password"
                value={form.password}
                onChange={e => updateField('password', e.target.value)}
                placeholder="至少 8 位字符"
                autoComplete="new-password"
                required
                style={inputStyle}
              />
            </div>

            <div style={{ marginBottom: '18px' }}>
              <label htmlFor="reset-email-code" style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--ink-secondary)', marginBottom: '7px', paddingLeft: '2px' }}>
                邮箱验证码
              </label>
              <div style={{ display: 'flex', gap: '12px' }}>
                <input
                  id="reset-email-code"
                  name="email_code"
                  type="text"
                  value={form.emailCode}
                  onChange={e => updateField('emailCode', e.target.value)}
                  placeholder="6 位验证码"
                  required
                  style={{ ...inputStyle, flex: 1 }}
                />
                <button
                  type="button"
                  disabled={codeSending || codeCountdown > 0 || !authConfigState.canUseAuthActions}
                  onClick={sendResetCode}
                  style={{
                    padding: '13px 20px',
                    fontSize: '13px',
                    fontWeight: 500,
                    color: codeCountdown > 0 ? 'var(--ink-secondary)' : 'var(--ink-inverse)',
                    background: codeCountdown > 0 ? 'var(--surface-hover)' : 'var(--ink)',
                    border: '1px solid ' + (codeCountdown > 0 ? 'var(--border)' : 'transparent'),
                    borderRadius: '10px',
                    cursor: codeSending || codeCountdown > 0 || !authConfigState.canUseAuthActions ? 'not-allowed' : 'pointer',
                    transition: 'background 0.2s ease',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {codeSending ? <Spinner /> : codeCountdown > 0 ? `${codeCountdown}s` : '重新发送'}
                </button>
              </div>
            </div>

            <button type="submit" disabled={authActionDisabled} style={btnPrimaryStyle(authActionDisabled)}>
              {loading ? <><Spinner /> 提交中...</> : '重置密码'}
            </button>

            <div style={{ marginTop: '18px', textAlign: 'center' }}>
              <Link to={buildAuthRoutePath('/login', { returnTo })} style={{ fontSize: '13px', color: 'var(--accent)', textDecoration: 'none', fontWeight: 500 }}>
                返回登录
              </Link>
            </div>
          </form>
        )}

        {authConfig && <TurnstileCaptcha config={authConfig} />}
      </div>
    </div>
  )
}
