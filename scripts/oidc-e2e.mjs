#!/usr/bin/env node

import assert from 'node:assert/strict'
import { createHash, randomBytes, webcrypto } from 'node:crypto'
import { fileURLToPath, pathToFileURL } from 'node:url'

const REQUIRED_ENV = [
  'GOAUTH_BASE_URL',
  'GOAUTH_TEST_EMAIL',
  'GOAUTH_TEST_PASSWORD',
  'GOAUTH_CLIENT_ID',
  'GOAUTH_CLIENT_SECRET',
  'GOAUTH_REDIRECT_URI',
]

const DEFAULT_SCOPE = 'openid profile email offline_access'
const CLOCK_SKEW_SECONDS = 60

export function readConfig(env = process.env) {
  return {
    baseURL: stripTrailingSlash(env.GOAUTH_BASE_URL || ''),
    email: env.GOAUTH_TEST_EMAIL || '',
    password: env.GOAUTH_TEST_PASSWORD || '',
    clientID: env.GOAUTH_CLIENT_ID || '',
    clientSecret: env.GOAUTH_CLIENT_SECRET || '',
    redirectURI: env.GOAUTH_REDIRECT_URI || '',
    scope: env.GOAUTH_SCOPE || DEFAULT_SCOPE,
    tokenAuthMethod: env.GOAUTH_TOKEN_AUTH_METHOD || 'post',
    insecureTLS: env.GOAUTH_INSECURE_TLS === '1',
    skipNegative: env.GOAUTH_SKIP_NEGATIVE === '1',
  }
}

export function validateConfig(config) {
  const missing = REQUIRED_ENV.filter((key) => {
    const field = {
      GOAUTH_BASE_URL: 'baseURL',
      GOAUTH_TEST_EMAIL: 'email',
      GOAUTH_TEST_PASSWORD: 'password',
      GOAUTH_CLIENT_ID: 'clientID',
      GOAUTH_CLIENT_SECRET: 'clientSecret',
      GOAUTH_REDIRECT_URI: 'redirectURI',
    }[key]
    return !String(config[field] || '').trim()
  })
  if (missing.length > 0) {
    throw new Error(`missing required env: ${missing.join(', ')}`)
  }

  try {
    const parsed = new URL(config.baseURL)
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error('GOAUTH_BASE_URL must use http or https')
    }
  } catch (error) {
    if (error.message.startsWith('GOAUTH_BASE_URL')) {
      throw error
    }
    throw new Error('GOAUTH_BASE_URL must be an absolute URL')
  }

  try {
    new URL(config.redirectURI)
  } catch {
    throw new Error('GOAUTH_REDIRECT_URI must be an absolute URL registered on the OAuth client')
  }

  if (!['post', 'basic'].includes(config.tokenAuthMethod)) {
    throw new Error('GOAUTH_TOKEN_AUTH_METHOD must be post or basic')
  }

  const scopes = new Set(String(config.scope).split(/\s+/).filter(Boolean))
  if (!scopes.has('openid')) {
    throw new Error('GOAUTH_SCOPE must include openid')
  }
}

export function buildAuthorizeURL(discovery, config, pkce, overrides = {}) {
  const authorizeURL = new URL(discovery.authorization_endpoint)
  authorizeURL.searchParams.set('response_type', 'code')
  authorizeURL.searchParams.set('client_id', overrides.clientID || config.clientID)
  authorizeURL.searchParams.set('redirect_uri', overrides.redirectURI || config.redirectURI)
  authorizeURL.searchParams.set('scope', overrides.scope || config.scope)
  authorizeURL.searchParams.set('state', overrides.state || randomToken(12))
  authorizeURL.searchParams.set('nonce', overrides.nonce || randomToken(12))
  authorizeURL.searchParams.set('code_challenge', overrides.codeChallenge || pkce.challenge)
  authorizeURL.searchParams.set('code_challenge_method', overrides.codeChallengeMethod || 'S256')
  return authorizeURL
}

async function run(config) {
  validateConfig(config)
  if (config.insecureTLS) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
  }

  const jar = new CookieJar()
  const discovery = await fetchJSON(joinURL(config.baseURL, '/.well-known/openid-configuration'))
  assert.equal(discovery.id_token_signing_alg_values_supported?.includes('RS256'), true)
  logOK('discovery')

  const jwks = await fetchJSON(discovery.jwks_uri)
  assert.ok(Array.isArray(jwks.keys) && jwks.keys.length > 0, 'JWKS must contain at least one key')
  logOK('jwks')

  const pkce = createPKCE()
  const state = randomToken(12)
  const nonce = randomToken(12)
  const authorizeURL = buildAuthorizeURL(discovery, config, pkce, { state, nonce })

  await assertLoginRedirect(authorizeURL)
  logOK('authorize redirects browser to login when SSO cookie is missing')

  await login(config, jar)
  logOK('password login sets browser SSO cookie')

  if (!config.skipNegative) {
    await assertBadRedirect(discovery, config, pkce, jar)
    logOK('negative: bad redirect_uri rejected')
  }

  const code = await authorizeForCode(authorizeURL, jar, state)
  logOK('authorization code issued')

  if (!config.skipNegative) {
    await expectTokenError(config, code, 'wrong-verifier', 'invalid_grant')
    logOK('negative: wrong PKCE verifier rejected')

    await expectTokenError({ ...config, clientSecret: 'wrong-client-secret' }, code, pkce.verifier, 'invalid_client')
    logOK('negative: wrong client_secret rejected')
  }

  const tokens = await exchangeCode(config, code, pkce.verifier)
  assert.ok(tokens.access_token, 'token response missing access_token')
  assert.ok(tokens.id_token, 'token response missing id_token')
  assert.ok(tokens.refresh_token, 'token response missing refresh_token; client must allow refresh_token and scope must include offline_access')
  logOK('authorization code exchanged for tokens')

  await verifyIDToken(tokens.id_token, jwks, {
    issuer: discovery.issuer,
    audience: config.clientID,
    nonce,
  })
  logOK('id_token signature and claims verified')

  const userinfo = await fetchJSON(discovery.userinfo_endpoint, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  })
  assert.ok(userinfo.sub, 'userinfo missing sub')
  logOK('userinfo')

  if (!config.skipNegative) {
    await expectTokenError(config, code, pkce.verifier, 'invalid_grant')
    logOK('negative: authorization code reuse rejected')
  }

  const rotated = await refreshToken(config, tokens.refresh_token)
  assert.ok(rotated.refresh_token && rotated.refresh_token !== tokens.refresh_token, 'refresh token was not rotated')
  logOK('refresh token rotation')

  if (!config.skipNegative) {
    await expectRefreshReuseRejected(config, tokens.refresh_token)
    logOK('negative: refresh token reuse rejected')
  }

  await revokeToken(config, rotated.refresh_token)
  logOK('refresh token revoke')

  await fetchJSON(joinURL(config.baseURL, '/oauth2/logout'))
  logOK('logout endpoint')
}

async function assertLoginRedirect(authorizeURL) {
  const response = await fetch(authorizeURL, {
    redirect: 'manual',
    headers: { Accept: 'text/html' },
  })
  assert.equal(response.status, 302)
  const location = response.headers.get('location') || ''
  assert.ok(location.includes('return_to='), `login redirect missing return_to: ${location}`)
}

async function assertBadRedirect(discovery, config, pkce, jar) {
  const badURL = buildAuthorizeURL(discovery, config, pkce, {
    redirectURI: 'https://invalid.example.com/callback',
  })
  const response = await fetch(badURL, {
    redirect: 'manual',
    headers: { Accept: 'text/html', Cookie: jar.header() },
  })
  await expectOAuthError(response, 400, 'invalid_request')
}

async function login(config, jar) {
  const response = await fetch(joinURL(config.baseURL, '/v1/auth/login'), {
    method: 'POST',
    redirect: 'manual',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      identifier: config.email,
      email: config.email,
      password: config.password,
    }),
  })
  jar.capture(response.headers)
  const body = await readJSON(response)
  assert.equal(response.status, 200, `login failed: ${JSON.stringify(body)}`)
  assert.ok(body?.data?.access_token, 'login response missing access_token')
  assert.ok(jar.header().includes('goauth_oidc_session='), 'login did not set goauth_oidc_session cookie')
}

async function authorizeForCode(authorizeURL, jar, expectedState) {
  const response = await fetch(authorizeURL, {
    redirect: 'manual',
    headers: { Accept: 'text/html', Cookie: jar.header() },
  })
  assert.equal(response.status, 302)
  const location = response.headers.get('location') || ''
  const redirect = new URL(location)
  assert.equal(redirect.searchParams.get('state'), expectedState)
  const code = redirect.searchParams.get('code')
  assert.ok(code, `authorization redirect missing code: ${location}`)
  return code
}

async function exchangeCode(config, code, verifier) {
  return tokenRequest(config, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.redirectURI,
    code_verifier: verifier,
  })
}

async function refreshToken(config, refreshTokenValue) {
  return tokenRequest(config, {
    grant_type: 'refresh_token',
    refresh_token: refreshTokenValue,
  })
}

async function tokenRequest(config, fields) {
  const response = await fetch(joinURL(config.baseURL, '/oauth2/token'), {
    method: 'POST',
    headers: tokenHeaders(config),
    body: tokenBody(config, fields),
  })
  const body = await readJSON(response)
  assert.equal(response.status, 200, `token endpoint failed: ${JSON.stringify(body)}`)
  return body
}

async function expectTokenError(config, code, verifier, expectedError) {
  const response = await fetch(joinURL(config.baseURL, '/oauth2/token'), {
    method: 'POST',
    headers: tokenHeaders(config),
    body: tokenBody(config, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: config.redirectURI,
      code_verifier: verifier,
    }),
  })
  await expectOAuthError(response, expectedError === 'invalid_client' ? 401 : 400, expectedError)
}

async function expectRefreshReuseRejected(config, refreshTokenValue) {
  const response = await fetch(joinURL(config.baseURL, '/oauth2/token'), {
    method: 'POST',
    headers: tokenHeaders(config),
    body: tokenBody(config, {
      grant_type: 'refresh_token',
      refresh_token: refreshTokenValue,
    }),
  })
  await expectOAuthError(response, 400, 'invalid_grant')
}

async function revokeToken(config, refreshTokenValue) {
  const response = await fetch(joinURL(config.baseURL, '/oauth2/revoke'), {
    method: 'POST',
    headers: tokenHeaders(config),
    body: tokenBody(config, { token: refreshTokenValue }),
  })
  assert.equal(response.status, 200, `revoke failed: ${await response.text()}`)
}

function tokenHeaders(config) {
  if (config.tokenAuthMethod === 'basic') {
    const credential = Buffer.from(`${config.clientID}:${config.clientSecret}`).toString('base64')
    return {
      Authorization: `Basic ${credential}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    }
  }
  return { 'Content-Type': 'application/x-www-form-urlencoded' }
}

function tokenBody(config, fields) {
  const body = new URLSearchParams(fields)
  if (config.tokenAuthMethod === 'post') {
    body.set('client_id', config.clientID)
    body.set('client_secret', config.clientSecret)
  }
  return body
}

async function verifyIDToken(rawToken, jwks, expected) {
  const { header, payload, signingInput, signature } = parseJWT(rawToken)
  assert.equal(header.alg, 'RS256')

  const jwk = jwks.keys.find((key) => key.kid === header.kid) || jwks.keys[0]
  assert.ok(jwk, `no JWKS key found for kid ${header.kid || '(empty)'}`)
  const key = await webcrypto.subtle.importKey(
    'jwk',
    { ...jwk, ext: true, key_ops: ['verify'] },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  )
  const valid = await webcrypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    signature,
    new TextEncoder().encode(signingInput),
  )
  assert.equal(valid, true, 'id_token signature is invalid')

  const now = Math.floor(Date.now() / 1000)
  assert.equal(payload.iss, expected.issuer)
  assert.ok(audienceIncludes(payload.aud, expected.audience), `aud ${JSON.stringify(payload.aud)} does not include ${expected.audience}`)
  assert.equal(payload.nonce, expected.nonce)
  assert.ok(payload.exp > now - CLOCK_SKEW_SECONDS, 'id_token is expired')
  if (payload.nbf !== undefined) {
    assert.ok(payload.nbf <= now + CLOCK_SKEW_SECONDS, 'id_token nbf is in the future')
  }
}

function parseJWT(rawToken) {
  const parts = rawToken.split('.')
  assert.equal(parts.length, 3, 'JWT must have three parts')
  return {
    header: JSON.parse(base64urlDecode(parts[0]).toString('utf8')),
    payload: JSON.parse(base64urlDecode(parts[1]).toString('utf8')),
    signingInput: `${parts[0]}.${parts[1]}`,
    signature: base64urlDecode(parts[2]),
  }
}

async function fetchJSON(url, init = {}) {
  const response = await fetch(url, init)
  const body = await readJSON(response)
  assert.equal(response.status, 200, `${url} failed: ${JSON.stringify(body)}`)
  return body
}

async function expectOAuthError(response, status, error) {
  const body = await readJSON(response)
  assert.equal(response.status, status, `status = ${response.status}, body=${JSON.stringify(body)}`)
  assert.equal(body.error, error)
}

async function readJSON(response) {
  const text = await response.text()
  if (!text) {
    return {}
  }
  try {
    return JSON.parse(text)
  } catch {
    throw new Error(`expected JSON response, got: ${text.slice(0, 200)}`)
  }
}

function createPKCE() {
  const verifier = randomToken(32)
  const challenge = createHash('sha256').update(verifier).digest('base64url')
  return { verifier, challenge }
}

function randomToken(bytes) {
  return randomBytes(bytes).toString('base64url')
}

function base64urlDecode(value) {
  return Buffer.from(value, 'base64url')
}

function audienceIncludes(audience, expected) {
  if (Array.isArray(audience)) {
    return audience.includes(expected)
  }
  return audience === expected
}

function joinURL(baseURL, path) {
  return new URL(path, `${stripTrailingSlash(baseURL)}/`).toString()
}

function stripTrailingSlash(value) {
  return String(value || '').replace(/\/+$/, '')
}

function logOK(message) {
  console.log(`[ok] ${message}`)
}

class CookieJar {
  constructor() {
    this.cookies = new Map()
  }

  capture(headers) {
    for (const value of getSetCookie(headers)) {
      const [pair] = value.split(';')
      const [name, ...rest] = pair.split('=')
      if (!name || rest.length === 0) {
        continue
      }
      this.cookies.set(name.trim(), rest.join('=').trim())
    }
  }

  header() {
    return [...this.cookies.entries()].map(([name, value]) => `${name}=${value}`).join('; ')
  }
}

function getSetCookie(headers) {
  if (typeof headers.getSetCookie === 'function') {
    return headers.getSetCookie()
  }
  const single = headers.get('set-cookie')
  return single ? [single] : []
}

function printHelp() {
  console.log(`Usage: node scripts/oidc-e2e.mjs [--check-config]\n\nRequired env:\n  GOAUTH_BASE_URL\n  GOAUTH_TEST_EMAIL\n  GOAUTH_TEST_PASSWORD\n  GOAUTH_CLIENT_ID\n  GOAUTH_CLIENT_SECRET\n  GOAUTH_REDIRECT_URI\n\nOptional env:\n  GOAUTH_SCOPE=${DEFAULT_SCOPE}\n  GOAUTH_TOKEN_AUTH_METHOD=post|basic\n  GOAUTH_SKIP_NEGATIVE=1\n  GOAUTH_INSECURE_TLS=1\n`)
}

export async function main(argv = process.argv.slice(2), env = process.env) {
  if (argv.includes('--help') || argv.includes('-h')) {
    printHelp()
    return
  }

  const config = readConfig(env)
  validateConfig(config)
  if (argv.includes('--check-config')) {
    console.log('OIDC e2e configuration looks valid')
    return
  }

  await run(config)
}

const isCLI = process.argv[1] && fileURLToPath(import.meta.url) === fileURLToPath(pathToFileURL(process.argv[1]))
if (isCLI) {
  main().catch((error) => {
    console.error(error?.stack || error?.message || String(error))
    process.exit(1)
  })
}
