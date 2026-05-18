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
                return { ok: true, path, data };
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
                  return { methods: [] };
                }
                if (path === '/account/authorized-apps') {
                  return { apps: [] };
                }
                if (path.startsWith('/account/activity')) {
                  return { items: [] };
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
  ]);
});
