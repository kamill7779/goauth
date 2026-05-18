import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

async function importLoginPageModule(relativePath) {
  const fullPath = path.resolve(relativePath);
  const outDir = await mkdtemp(path.join(tmpdir(), 'goauth-login-page-'));
  const outFile = path.join(outDir, path.basename(relativePath).replace(/\.tsx$/, '.cjs'));
  await build({
    entryPoints: [fullPath],
    outfile: outFile,
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'es2022',
    define: {
      'import.meta.env.VITE_API_BASE_URL': '"http://goauth.test"',
    },
  });
  return import(pathToFileURL(outFile).href);
}

const loginPage = await importLoginPageModule('src/pages/LoginPage.tsx');

test('buildAuthRoutePath preserves return_to through reset-password navigation', () => {
  const nextPath = loginPage.buildAuthRoutePath('/reset-password', {
    email: 'member@example.com',
    returnTo: '/oauth2/authorize?client_id=demo-web&state=opaque-state',
  });
  const parsed = new URL(nextPath, 'http://goauth.test');

  assert.equal(parsed.pathname, '/reset-password');
  assert.equal(parsed.searchParams.get('email'), 'member@example.com');
  assert.equal(
    parsed.searchParams.get('return_to'),
    '/oauth2/authorize?client_id=demo-web&state=opaque-state',
  );
});

test('buildAuthRoutePath omits empty return_to', () => {
  const nextPath = loginPage.buildAuthRoutePath('/login', {
    returnTo: '',
  });
  const parsed = new URL(nextPath, 'http://goauth.test');

  assert.equal(parsed.pathname, '/login');
  assert.equal(parsed.searchParams.has('return_to'), false);
});

test('resolvePostLoginRedirect sends direct logins to account center', () => {
  assert.deepEqual(loginPage.resolvePostLoginRedirect(''), {
    mode: 'app',
    target: '/account',
  });
});

test('resolvePostLoginRedirect preserves SSO authorize return_to', () => {
  assert.deepEqual(loginPage.resolvePostLoginRedirect('/oauth2/authorize?client_id=demo-web'), {
    mode: 'external',
    target: '/oauth2/authorize?client_id=demo-web',
  });
});

test('normalizeAuthorizeReturnTo accepts cross-origin authorize return_to from configured issuer origin', () => {
  const returnTo = loginPage.normalizeAuthorizeReturnTo(
    'https://identity.example.com/oauth2/authorize?client_id=demo-web&state=opaque-state',
    {
      currentOrigin: 'https://console.example.com',
      apiBaseURL: 'https://api.example.com',
      issuerURL: 'https://identity.example.com',
    },
  );

  assert.equal(
    returnTo,
    'https://identity.example.com/oauth2/authorize?client_id=demo-web&state=opaque-state',
  );
});

test('normalizeAuthorizeReturnTo accepts API origin when issuer is not configured', () => {
  const returnTo = loginPage.normalizeAuthorizeReturnTo(
    'https://identity.example.com/oauth2/authorize?client_id=demo-web&state=opaque-state',
    {
      currentOrigin: 'https://console.example.com',
      apiBaseURL: 'https://identity.example.com',
      issuerURL: '',
    },
  );

  assert.equal(
    returnTo,
    'https://identity.example.com/oauth2/authorize?client_id=demo-web&state=opaque-state',
  );
});

test('normalizeAuthorizeReturnTo rejects cross-origin authorize return_to from api origin when issuer differs', () => {
  const returnTo = loginPage.normalizeAuthorizeReturnTo(
    'https://api.example.com/oauth2/authorize?client_id=demo-web&state=opaque-state',
    {
      currentOrigin: 'https://console.example.com',
      apiBaseURL: 'https://api.example.com',
      issuerURL: 'https://identity.example.com',
    },
  );

  assert.equal(returnTo, '');
});

test('normalizeAuthorizeReturnTo rejects authorize targets from untrusted origins', () => {
  const returnTo = loginPage.normalizeAuthorizeReturnTo(
    'https://evil.example.com/oauth2/authorize?client_id=demo-web',
    {
      currentOrigin: 'https://console.example.com',
      apiBaseURL: 'https://api.example.com',
      issuerURL: 'https://identity.example.com',
    },
  );

  assert.equal(returnTo, '');
});

test('authEntryVisibility hides register and local login from runtime config', () => {
  const visibility = loginPage.authEntryVisibility({
    registration: { mode: 'disabled' },
    local_login: { enabled: false },
    external_providers: [
      { slug: 'github', display_name: 'GitHub', start_url: '/v1/external/github/start' },
    ],
  });

  assert.equal(visibility.showRegister, false);
  assert.equal(visibility.showLocalLogin, false);
  assert.equal(visibility.githubProvider.display_name, 'GitHub');
});

test('buildExternalProviderStartURL preserves return_to for GitHub login', () => {
  const startURL = loginPage.buildExternalProviderStartURL(
    { slug: 'github', display_name: 'GitHub', start_url: '/v1/external/github/start' },
    '/oauth2/authorize?client_id=demo-web&state=opaque-state',
    'https://identity.example.com',
  );
  const parsed = new URL(startURL);

  assert.equal(parsed.origin, 'https://identity.example.com');
  assert.equal(parsed.pathname, '/v1/external/github/start');
  assert.equal(parsed.searchParams.get('return_to'), '/oauth2/authorize?client_id=demo-web&state=opaque-state');
});

test('buildExternalProviderStartURL preserves trusted absolute authorize return_to', () => {
  const startURL = loginPage.buildExternalProviderStartURL(
    { slug: 'github', display_name: 'GitHub', start_url: '/v1/external/github/start' },
    'https://identity.example.com/oauth2/authorize?client_id=demo-web&state=opaque-state',
    'https://identity.example.com',
  );
  const parsed = new URL(startURL);

  assert.equal(parsed.origin, 'https://identity.example.com');
  assert.equal(parsed.searchParams.get('return_to'), 'https://identity.example.com/oauth2/authorize?client_id=demo-web&state=opaque-state');
});

test('buildAuthConfigViewState keeps auth actions unavailable until runtime config loads', () => {
  const loadingState = loginPage.buildAuthConfigViewState(null, true, '');
  assert.equal(loadingState.canUseAuthActions, false);
  assert.equal(loadingState.visibility.showRegister, false);
  assert.equal(loadingState.visibility.showLocalLogin, false);

  const failedState = loginPage.buildAuthConfigViewState(null, false, 'boom');
  assert.equal(failedState.canUseAuthActions, false);
  assert.equal(failedState.statusMessage, '认证配置不可用，请稍后重试');
});

test('loginTwoFactorPayloadFromInput treats 6 digits as TOTP code', () => {
  assert.deepEqual(loginPage.loginTwoFactorPayloadFromInput('123 456'), {
    code: '123456',
  });
});

test('loginTwoFactorPayloadFromInput treats non-6-digit input as recovery code', () => {
  assert.deepEqual(loginPage.loginTwoFactorPayloadFromInput('ABCD-EFGH-IJKL'), {
    recovery_code: 'ABCD-EFGH-IJKL',
  });
});
