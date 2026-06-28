import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

async function importAuthModule(relativePath) {
  const fullPath = path.resolve(relativePath);
  const outDir = await mkdtemp(path.join(tmpdir(), 'goauth-auth-api-'));
  const outFile = path.join(outDir, 'auth.cjs');

  await build({
    entryPoints: [fullPath],
    outfile: outFile,
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'es2022',
    plugins: [
      {
        name: 'stub-auth-client',
        setup(buildApi) {
          buildApi.onResolve({ filter: /^\.\/client$/ }, () => ({
            path: 'client-stub',
            namespace: 'auth-client-stub',
          }));
          buildApi.onLoad({ filter: /.*/, namespace: 'auth-client-stub' }, () => ({
            contents: `
              export async function apiPost(path, data, options) {
                globalThis.__authClientCalls.push({ method: 'post', path, data, options });
                return { ok: true, path, data };
              }

              export async function apiPostV1(path, data, options) {
                globalThis.__authClientCalls.push({ method: 'postV1', path, data, options });
                if (path === '/account/2fa/setup/start') {
                  return { secret: 'JBSWY3DPEHPK3PXP', otpauth_url: 'otpauth://totp/GoAuth:member@example.com' };
                }
                if (path === '/account/2fa/verify') {
                  return { verified: true, recovery_codes: ['RC-1111', 'RC-2222'] };
                }
                if (path === '/account/2fa/disable') {
                  return { disabled: true };
                }
                if (path === '/account/2fa/recovery-codes/regenerate') {
                  return { recovery_codes: ['RC-3333', 'RC-4444'] };
                }
                if (path === '/account/login-methods/github/bind/start') {
                  return { start_url: 'https://github.com/login/oauth/authorize?state=bind-state' };
                }
                return { ok: true, path, data };
              }

              export async function apiPostFormV1(path, data) {
                globalThis.__authClientCalls.push({ method: 'postFormV1', path, data });
                return { avatar_url: '/uploads/avatars/member.png' };
              }

              export async function apiPatchV1(path, data) {
                globalThis.__authClientCalls.push({ method: 'patchV1', path, data });
                return { ok: true, path, data };
              }

              export async function apiDeleteV1(path) {
                globalThis.__authClientCalls.push({ method: 'deleteV1', path });
                if (path === '/account/login-methods/github') {
                  return { unbound: true };
                }
                return { ok: true, path };
              }

              export async function apiGetV1(path) {
                globalThis.__authClientCalls.push({ method: 'getV1', path });
                if (path === '/account/me') {
                  return {
                    user: { timezone: '' },
                    session: { id: 'session-1', tenant_id: 0 },
                    is_admin: false,
                  };
                }
                if (path === '/account/sessions') {
                  return { sessions: [] };
                }
                if (path === '/account/login-methods') {
                  return { methods: globalThis.__accountLoginMethodsStub ?? [] };
                }
                if (path === '/account/authorized-apps') {
                  return { apps: [] };
                }
                if (path.startsWith('/account/activity')) {
                  return { items: [] };
                }
                if (path === '/account/2fa/status') {
                  return {
                    enabled: true,
                    method: 'totp',
                    recovery_codes_available: true,
                    pending_setup: false,
                  };
                }
                return { ok: true, path };
              }

              export async function apiGet(path) {
                globalThis.__authClientCalls.push({ method: 'get', path });
                return { ok: true, path };
              }
            `,
            loader: 'js',
          }));
        },
      },
    ],
  });

  return import(pathToFileURL(outFile).href);
}

globalThis.__authClientCalls = [];
globalThis.__accountLoginMethodsStub = [];
globalThis.window = {
  location: { origin: 'http://goauth.test' },
  localStorage: { getItem: () => null },
};

const { exchangeGitHubLogin, forgotPassword, register, resetPassword, startGitHubLogin, verifyLogin2FA } = await importAuthModule('src/api/auth.ts');
const account = await importAuthModule('src/api/account.ts');

test('forgotPassword posts email to forgot-password endpoint', async () => {
  globalThis.__authClientCalls.length = 0;

  await forgotPassword('member@example.com');

  assert.deepEqual(globalThis.__authClientCalls, [
    {
      method: 'post',
      path: '/password/forgot',
      data: { email: 'member@example.com' },
      options: undefined,
    },
  ]);
});

test('resetPassword posts email code and new password to reset endpoint', async () => {
  globalThis.__authClientCalls.length = 0;

  await resetPassword({
    email: 'member@example.com',
    email_code: '493021',
    new_password: 'new-password-123',
  });

  assert.deepEqual(globalThis.__authClientCalls, [
    {
      method: 'post',
      path: '/password/reset',
      data: {
        email: 'member@example.com',
        email_code: '493021',
        new_password: 'new-password-123',
      },
      options: undefined,
    },
  ]);
});

test('forgotPassword forwards captcha token when provided', async () => {
  globalThis.__authClientCalls.length = 0;

  await forgotPassword('member@example.com', { captchaToken: 'captcha-proof' });

  assert.deepEqual(globalThis.__authClientCalls, [
    {
      method: 'post',
      path: '/password/forgot',
      data: { email: 'member@example.com' },
      options: { captchaToken: 'captcha-proof' },
    },
  ]);
});

test('register forwards captcha and human check tokens when provided', async () => {
  globalThis.__authClientCalls.length = 0;

  await register({
    username: 'member',
    nickname: 'Member',
    email: 'member@example.com',
    password: 'password-123',
    email_code: '493021',
  }, { captchaToken: 'captcha-proof', humanToken: 'human-proof' });

  assert.deepEqual(globalThis.__authClientCalls, [
    {
      method: 'post',
      path: '/register',
      data: {
        username: 'member',
        nickname: 'Member',
        email: 'member@example.com',
        password: 'password-123',
        email_code: '493021',
      },
      options: { captchaToken: 'captcha-proof', humanToken: 'human-proof' },
    },
  ]);
});

test('exchangeGitHubLogin posts code to external GitHub exchange endpoint', async () => {
  globalThis.__authClientCalls.length = 0;

  await exchangeGitHubLogin('exchange-code');

  assert.deepEqual(globalThis.__authClientCalls, [
    {
      method: 'postV1',
      path: '/external/github/exchange',
      data: { code: 'exchange-code' },
      options: undefined,
    },
  ]);
});

test('verifyLogin2FA posts challenge code to login 2FA endpoint', async () => {
  globalThis.__authClientCalls.length = 0;

  await verifyLogin2FA({ challenge_id: 'challenge-123', code: '123456' });

  assert.deepEqual(globalThis.__authClientCalls, [
    {
      method: 'post',
      path: '/login/2fa/verify',
      data: { challenge_id: 'challenge-123', code: '123456' },
      options: undefined,
    },
  ]);
});

test('startGitHubLogin posts return_to and captcha token to external GitHub start endpoint', async () => {
  globalThis.__authClientCalls.length = 0;

  await startGitHubLogin({
    return_to: '/oauth2/authorize?client_id=demo-web&state=opaque-state',
  }, { captchaToken: 'captcha-proof' });

  assert.deepEqual(globalThis.__authClientCalls, [
    {
      method: 'postV1',
      path: '/external/github/start',
      data: {
        return_to: '/oauth2/authorize?client_id=demo-web&state=opaque-state',
      },
      options: { captchaToken: 'captcha-proof' },
    },
  ]);
});

test('account API uses self-service v1 account routes', async () => {
  globalThis.__authClientCalls.length = 0;

  await account.getAccountMe();
  await account.getAccountSessions();
  await account.revokeAccountSession('session/with?chars');
  await account.logoutAllAccountSessions();
  await account.getAccountActivity(5);
  await account.changeAccountPassword({ current: 'old-password-123', newPass: 'new-password-456' });

  assert.deepEqual(globalThis.__authClientCalls, [
    { method: 'getV1', path: '/account/me' },
    { method: 'getV1', path: '/account/sessions' },
    {
      method: 'postV1',
      path: '/account/sessions/session%2Fwith%3Fchars/revoke',
      data: undefined,
      options: undefined,
    },
    {
      method: 'postV1',
      path: '/account/logout-all',
      data: undefined,
      options: undefined,
    },
    { method: 'getV1', path: '/account/activity?limit=5' },
    {
      method: 'postV1',
      path: '/account/password/change',
      data: {
        current_password: 'old-password-123',
        new_password: 'new-password-456',
      },
      options: undefined,
    },
  ]);
});

test('password login method remains enabled for password changes', async () => {
  globalThis.__authClientCalls.length = 0;
  globalThis.__accountLoginMethodsStub = [
    {
      key: 'password',
      type: 'password',
      label: '密码',
      bound: true,
      status: 'enabled',
      verified: true,
      identifier: '已设置密码',
      can_unbind: false,
    },
  ];

  const result = await account.getAccountLoginMethods();
  const passwordMethod = result.methods.find((method) => method.id === 'password');

  assert.equal(passwordMethod?.disabled, false);
  assert.equal(passwordMethod?.disabledReason, undefined);
});

test('github login method is offered for account binding when unbound', async () => {
  globalThis.__authClientCalls.length = 0;
  globalThis.__accountLoginMethodsStub = [];

  const result = await account.getAccountLoginMethods();
  const githubMethod = result.methods.find((method) => method.id === 'github');

  assert.equal(githubMethod?.bound, false);
  assert.equal(githubMethod?.disabled, false);
  assert.equal(githubMethod?.disabledReason, undefined);
});

test('uploadAccountAvatar posts multipart avatar form data', async () => {
  globalThis.__authClientCalls.length = 0;

  const file = new File(['avatar-bytes'], 'avatar.png', { type: 'image/png' });
  const result = await account.uploadAccountAvatar(file);

  assert.equal(result.avatar_url, '/uploads/avatars/member.png');
  assert.equal(globalThis.__authClientCalls.length, 1);
  assert.equal(globalThis.__authClientCalls[0].method, 'postFormV1');
  assert.equal(globalThis.__authClientCalls[0].path, '/account/avatar');
  assert.equal(globalThis.__authClientCalls[0].data.get('avatar'), file);
});

test('updateAccountProfile does not send immutable username', async () => {
  globalThis.__authClientCalls.length = 0;

  await account.updateAccountProfile({
    nickname: 'Member',
    display_name: 'Member',
    username: 'stable-user',
    email: 'member@example.com',
    locale: 'zh-CN',
    timezone: 'Asia/Shanghai',
  });

  assert.deepEqual(globalThis.__authClientCalls, [
    {
      method: 'patchV1',
      path: '/account/profile',
      data: {
        nickname: 'Member',
        display_name: 'Member',
        locale: 'zh-CN',
      },
    },
  ]);
});

test('account 2FA API maps lifecycle routes and response fields', async () => {
  globalThis.__authClientCalls.length = 0;

  const status = await account.getAccount2FAStatus();
  const setup = await account.enable2FA();
  const verified = await account.verify2FASetup('123456');
  const disabled = await account.disable2FA('654321');
  const regenerated = await account.regenerateRecoveryCodes('111222');

  assert.deepEqual(status, { enabled: true, recoveryCodesAvailable: true, pendingSetup: false, method: 'totp' });
  assert.deepEqual(setup, { secret: 'JBSWY3DPEHPK3PXP', qrUrl: 'otpauth://totp/GoAuth:member@example.com' });
  assert.deepEqual(verified, { verified: true, codes: ['RC-1111', 'RC-2222'] });
  assert.deepEqual(disabled, { disabled: true });
  assert.deepEqual(regenerated, { codes: ['RC-3333', 'RC-4444'] });
  assert.deepEqual(globalThis.__authClientCalls, [
    { method: 'getV1', path: '/account/2fa/status' },
    { method: 'postV1', path: '/account/2fa/setup/start', data: {}, options: undefined },
    { method: 'postV1', path: '/account/2fa/verify', data: { code: '123456' }, options: undefined },
    { method: 'postV1', path: '/account/2fa/disable', data: { code: '654321' }, options: undefined },
    { method: 'postV1', path: '/account/2fa/recovery-codes/regenerate', data: { code: '111222' }, options: undefined },
  ]);
});

test('account login method bind and unbind use generic provider routes', async () => {
  globalThis.__authClientCalls.length = 0;

  const bind = await account.bindLoginMethod('github');
  const unbind = await account.unbindLoginMethod('github');

  assert.deepEqual(bind, {
    bound: false,
    redirectUrl: 'https://github.com/login/oauth/authorize?state=bind-state',
  });
  assert.deepEqual(unbind, { unbound: true });
  assert.deepEqual(globalThis.__authClientCalls, [
    {
      method: 'postV1',
      path: '/account/login-methods/github/bind/start',
      data: { return_to: 'http://goauth.test/account' },
      options: undefined,
    },
    { method: 'deleteV1', path: '/account/login-methods/github' },
  ]);
});
