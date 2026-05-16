import test from 'node:test'
import assert from 'node:assert/strict'

import { buildAuthorizeURL, readConfig, validateConfig } from './oidc-e2e.mjs'

const validEnv = {
  GOAUTH_BASE_URL: 'https://auth.example.com',
  GOAUTH_TEST_EMAIL: 'user@example.com',
  GOAUTH_TEST_PASSWORD: 'not-a-real-password',
  GOAUTH_CLIENT_ID: 'demo-web',
  GOAUTH_CLIENT_SECRET: 'not-a-real-secret',
  GOAUTH_REDIRECT_URI: 'https://app.example.com/callback',
}

test('readConfig maps required environment without exposing secrets in errors', () => {
  const config = readConfig(validEnv)

  assert.equal(config.baseURL, 'https://auth.example.com')
  assert.equal(config.clientID, 'demo-web')
  assert.equal(config.tokenAuthMethod, 'post')
  assert.equal(config.scope, 'openid profile email offline_access')
  assert.doesNotThrow(() => validateConfig(config))
})

test('validateConfig reports missing required variable names', () => {
  assert.throws(
    () => validateConfig(readConfig({ ...validEnv, GOAUTH_CLIENT_SECRET: '' })),
    /GOAUTH_CLIENT_SECRET/,
  )
})

test('validateConfig rejects unsupported token auth methods', () => {
  assert.throws(
    () => validateConfig(readConfig({ ...validEnv, GOAUTH_TOKEN_AUTH_METHOD: 'none' })),
    /GOAUTH_TOKEN_AUTH_METHOD/,
  )
})

test('buildAuthorizeURL creates an authorization code PKCE request', () => {
  const url = buildAuthorizeURL(
    { authorization_endpoint: 'https://auth.example.com/oauth2/authorize' },
    readConfig(validEnv),
    { challenge: 'pkce-challenge' },
    { state: 'state-1', nonce: 'nonce-1' },
  )

  assert.equal(url.searchParams.get('response_type'), 'code')
  assert.equal(url.searchParams.get('client_id'), 'demo-web')
  assert.equal(url.searchParams.get('redirect_uri'), 'https://app.example.com/callback')
  assert.equal(url.searchParams.get('scope'), 'openid profile email offline_access')
  assert.equal(url.searchParams.get('code_challenge'), 'pkce-challenge')
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256')
  assert.equal(url.searchParams.get('state'), 'state-1')
  assert.equal(url.searchParams.get('nonce'), 'nonce-1')
})
