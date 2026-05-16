import { useEffect, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { exchangeGitHubLogin } from '../api/auth'
import { defaultPublicConfig, getPublicConfig } from '../api/publicConfig'
import { API_BASE_URL } from '../api/client'
import ThemeToggle from '../components/admin/ThemeToggle'
import BrandMark from '../components/BrandMark'
import type { PublicAuthConfig } from '../types/publicConfig'
import type { LoginResponse } from '../types/auth'

type TokenStorage = Pick<Storage, 'setItem'>
type RedirectOptions = {
  currentOrigin?: string
  apiBaseURL?: string
  issuerURL?: string
}

const OIDC_ISSUER_URL = import.meta.env?.VITE_OIDC_ISSUER_URL?.trim() ?? ''

export function externalCallbackStateFromSearch(search: string): { provider: string; code: string } {
  return externalCallbackStateFromLocation(search, '')
}

export function externalCallbackStateFromLocation(search: string, hash: string): { provider: string; code: string } {
  const params = new URLSearchParams(search)
  const fragment = new URLSearchParams(hash.replace(/^#/, ''))
  return {
    provider: fragment.get('provider')?.trim() || params.get('provider')?.trim() || '',
    code: fragment.get('code')?.trim() || params.get('code')?.trim() || '',
  }
}

export function storeExternalLoginTokens(storage: TokenStorage, tokens: LoginResponse) {
  storage.setItem('access_token', tokens.access_token)
  storage.setItem('refresh_token', tokens.refresh_token)
}

function originFromURL(raw: string, fallback: string): string | null {
  try {
    return new URL(raw, fallback).origin
  } catch {
    return null
  }
}

function trustedAuthorizeOrigins(options: Required<RedirectOptions>): Set<string> {
  const origins = new Set<string>()
  const issuerURL = options.issuerURL.trim()
  const origin = originFromURL(issuerURL || options.apiBaseURL, options.currentOrigin)
  if (origin) {
    origins.add(origin)
  }
  return origins
}

export function externalCallbackURLWithoutExchangeCode(raw: string): string {
  try {
    const url = new URL(raw, 'http://goauth.local')
    url.searchParams.delete('provider')
    url.searchParams.delete('code')
    const fragmentParams = new URLSearchParams(url.hash.replace(/^#/, ''))
    if (fragmentParams.has('provider') || fragmentParams.has('code')) {
      fragmentParams.delete('provider')
      fragmentParams.delete('code')
      const fragment = fragmentParams.toString()
      url.hash = fragment ? `#${fragment}` : ''
    }
    const query = url.searchParams.toString()
    return `${url.pathname}${query ? `?${query}` : ''}${url.hash}`
  } catch {
    return '/external/callback'
  }
}

export function resolveExternalRedirect(raw: string | undefined, options?: RedirectOptions): string {
  const value = raw?.trim() ?? ''
  if (!value) {
    return '/admin'
  }
  const redirectOptions: Required<RedirectOptions> = {
    currentOrigin: options?.currentOrigin?.trim() || (typeof window !== 'undefined' ? window.location.origin : 'http://goauth.local'),
    apiBaseURL: options?.apiBaseURL?.trim() || API_BASE_URL,
    issuerURL: options?.issuerURL?.trim() || OIDC_ISSUER_URL,
  }
  const currentOrigin = originFromURL(redirectOptions.currentOrigin, 'http://goauth.local') ?? 'http://goauth.local'
  const authorizeOrigins = trustedAuthorizeOrigins({ ...redirectOptions, currentOrigin })

  try {
    const parsed = new URL(value, currentOrigin)
    if (!parsed.pathname.startsWith('/') || parsed.pathname.startsWith('//')) {
      return '/admin'
    }
    if (parsed.origin !== currentOrigin) {
      if (parsed.pathname === '/oauth2/authorize' && authorizeOrigins.has(parsed.origin)) {
        return parsed.toString()
      }
      return '/admin'
    }
    return parsed.pathname + parsed.search
  } catch {
    return '/admin'
  }
}

export default function ExternalCallbackPage() {
  const location = useLocation()
  const [publicConfig, setPublicConfig] = useState<PublicAuthConfig>(defaultPublicConfig)
  const [configReady, setConfigReady] = useState(false)
  const [{ error, loading }, setState] = useState({ error: '', loading: true })
  const brand = publicConfig.brand

  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.history.replaceState(window.history.state, document.title, externalCallbackURLWithoutExchangeCode(window.location.href))
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    getPublicConfig()
      .then(config => {
        if (!cancelled) {
          setPublicConfig(config)
        }
      })
      .catch(() => {
        if (!cancelled) {
          setPublicConfig(defaultPublicConfig)
        }
      })
      .finally(() => {
        if (!cancelled) {
          setConfigReady(true)
        }
      })
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    if (!configReady) {
      return
    }
    let cancelled = false
    const { provider, code } = externalCallbackStateFromLocation(location.search, location.hash)
    if (provider !== 'github' || !code) {
      setState({ error: '登录回调缺少有效凭据', loading: false })
      return
    }

    exchangeGitHubLogin(code)
      .then((result) => {
        if (cancelled) {
          return
        }
        storeExternalLoginTokens(window.localStorage, result.tokens)
        window.location.assign(resolveExternalRedirect(result.return_to, {
          apiBaseURL: API_BASE_URL,
          issuerURL: publicConfig.issuer_url,
        }))
      })
      .catch((err) => {
        if (!cancelled) {
          setState({ error: err instanceof Error ? err.message : '登录失败', loading: false })
        }
      })

    return () => {
      cancelled = true
    }
  }, [configReady, location.search, location.hash, publicConfig.issuer_url])

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '40px 24px',
        background: 'var(--bg)',
      }}
    >
      <div style={{ position: 'fixed', top: 24, right: 24, zIndex: 10 }}>
        <ThemeToggle variant="inline" />
      </div>
      <div
        style={{
          width: '100%',
          maxWidth: '420px',
          background: 'var(--surface-solid)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          boxShadow: 'var(--shadow-md)',
          padding: '40px',
          textAlign: 'center',
        }}
      >
        <div style={{ marginBottom: '28px' }}>
          <BrandMark brand={brand} size="md" orientation="stacked" align="center" showTagline />
        </div>
        <h1 style={{ fontSize: '22px', fontWeight: 600, color: 'var(--ink)', marginBottom: '10px' }}>
          {loading ? '正在完成登录' : '登录未完成'}
        </h1>
        <p style={{ fontSize: '14px', lineHeight: 1.6, color: error ? 'var(--error)' : 'var(--ink-secondary)' }}>
          {error || '请稍候'}
        </p>
        {error && (
          <div style={{ marginTop: '22px' }}>
            <Link to="/login" style={{ color: 'var(--accent)', fontSize: '14px', fontWeight: 500, textDecoration: 'none' }}>
              返回登录
            </Link>
          </div>
        )}
      </div>
    </div>
  )
}
