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

const { exchangeGitHubLogin, forgotPassword, resetPassword } = await importAuthModule('src/api/auth.ts');
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
