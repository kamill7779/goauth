import { useEffect, useRef } from 'react'
import type { PublicAuthConfig } from '../../types/publicConfig'

type TurnstileAPI = {
  render: (container: HTMLElement, options: Record<string, unknown>) => string
  execute: (widgetId: string) => void
  reset: (widgetId: string) => void
  remove?: (widgetId: string) => void
}

declare global {
  interface Window {
    turnstile?: TurnstileAPI
  }
}

const turnstileScriptID = 'goauth-turnstile-script'
let turnstileScriptPromise: Promise<void> | null = null

export function buildTurnstileRenderOptions({
  siteKey,
  onSuccess,
  onError,
  onExpired,
}: {
  siteKey: string
  onSuccess: (token: string) => void
  onError: () => void
  onExpired: () => void
}): Record<string, unknown> {
  return {
    sitekey: siteKey,
    execution: 'execute',
    appearance: 'interaction-only',
    'response-field': false,
    callback: onSuccess,
    'error-callback': onError,
    'expired-callback': onExpired,
  }
}

function loadTurnstileScript(): Promise<void> {
  if (typeof window === 'undefined') {
    return Promise.resolve()
  }
  if (window.turnstile) {
    return Promise.resolve()
  }
  if (turnstileScriptPromise) {
    return turnstileScriptPromise
  }

  turnstileScriptPromise = new Promise((resolve, reject) => {
    const existing = document.getElementById(turnstileScriptID) as HTMLScriptElement | null
    if (existing) {
      existing.addEventListener('load', () => resolve(), { once: true })
      existing.addEventListener('error', () => reject(new Error('Turnstile script failed to load')), { once: true })
      return
    }

    const script = document.createElement('script')
    script.id = turnstileScriptID
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
    script.async = true
    script.defer = true
    script.addEventListener('load', () => resolve(), { once: true })
    script.addEventListener('error', () => reject(new Error('Turnstile script failed to load')), { once: true })
    document.head.appendChild(script)
  })
  return turnstileScriptPromise
}

export default function TurnstileCaptcha({ config }: { config: PublicAuthConfig }) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const pendingRef = useRef<{
    resolve: (token: string) => void
    reject: (error: Error) => void
  } | null>(null)

  useEffect(() => {
    if (config.captcha.provider !== 'turnstile' || !config.captcha.site_key) {
      return
    }

    let cancelled = false
    let widgetId = ''
    const previousBridge = window.__goauthCaptcha

    loadTurnstileScript()
      .then(() => {
        if (cancelled || !containerRef.current || !window.turnstile) {
          return
        }
        widgetId = window.turnstile.render(containerRef.current, buildTurnstileRenderOptions({
          siteKey: config.captcha.site_key,
          onSuccess: (token: string) => {
            pendingRef.current?.resolve(token)
            pendingRef.current = null
          },
          onError: () => {
            pendingRef.current?.reject(new Error('CAPTCHA 验证失败，请重试'))
            pendingRef.current = null
          },
          onExpired: () => {
            pendingRef.current?.reject(new Error('CAPTCHA 已过期，请重试'))
            pendingRef.current = null
          },
        }))

        window.__goauthCaptcha = {
          getToken: async ({ action }) => {
            if (!config.captcha.actions.includes(action)) {
              return undefined
            }
            if (!window.turnstile || !widgetId) {
              throw new Error('CAPTCHA 尚未准备好，请稍后重试')
            }
            return new Promise<string>((resolve, reject) => {
              pendingRef.current = { resolve, reject }
              window.turnstile?.reset(widgetId)
              window.turnstile?.execute(widgetId)
            })
          },
        }
      })
      .catch(() => {
        window.__goauthCaptcha = previousBridge
      })

    return () => {
      cancelled = true
      pendingRef.current = null
      if (window.__goauthCaptcha !== previousBridge) {
        window.__goauthCaptcha = previousBridge
      }
      if (widgetId && window.turnstile?.remove) {
        window.turnstile.remove(widgetId)
      }
    }
  }, [config.captcha.actions, config.captcha.provider, config.captcha.site_key])

  return (
    <div
      ref={containerRef}
      className="goauth-captcha-slot"
    />
  )
}
