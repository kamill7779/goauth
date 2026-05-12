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
              export async function apiPost(path, data) {
                globalThis.__authClientCalls.push({ method: 'post', path, data });
                return { ok: true, path, data };
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

const { forgotPassword, resetPassword } = await importAuthModule('src/api/auth.ts');

test('forgotPassword posts email to forgot-password endpoint', async () => {
  globalThis.__authClientCalls.length = 0;

  await forgotPassword('member@example.com');

  assert.deepEqual(globalThis.__authClientCalls, [
    {
      method: 'post',
      path: '/password/forgot',
      data: { email: 'member@example.com' },
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
    },
  ]);
});
