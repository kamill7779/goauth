import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

async function importBundledTsx(relativePath) {
  const fullPath = path.resolve(relativePath);
  const outDir = await mkdtemp(path.join(tmpdir(), 'goauth-oauth-page-'));
  const outFile = path.join(outDir, path.basename(relativePath).replace(/\.tsx$/, '.cjs'));
  await build({
    entryPoints: [fullPath],
    outfile: outFile,
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'es2022',
    jsx: 'automatic',
    define: {
      'import.meta.env.VITE_API_BASE_URL': '"http://goauth.test"',
    },
  });
  return import(pathToFileURL(outFile).href);
}

const oauthPage = await importBundledTsx('src/pages/Admin/OAuthPage.tsx');

const existingClient = {
  client_id: 'admin-web',
  name: 'Admin Web',
  redirect_uris: ['https://admin.example.com/callback'],
  scopes: ['openid', 'profile'],
  status: 'active',
  auto_provision_members: true,
  last_rotated: '2026-05-12T08:00:00Z',
};

test('applyRotateSecretOutcome replaces stale secret and emits success toast when backend returns new secret', () => {
  const outcome = oauthPage.applyRotateSecretOutcome({
    currentNotice: {
      clientId: 'legacy-client',
      secret: 'legacy-secret',
      source: 'rotate',
    },
    result: {
      client: {
        ...existingClient,
        last_rotated: '2026-05-12T09:00:00Z',
      },
      client_secret: 'fresh-secret',
    },
  });

  assert.deepEqual(outcome, {
    secretNotice: {
      clientId: 'admin-web',
      secret: 'fresh-secret',
      source: 'rotate',
    },
    toast: {
      message: 'admin-web 密钥已轮换',
      type: 'success',
    },
  });
});

test('applyRotateSecretOutcome clears stale secret and shows error when backend omits one-time secret', () => {
  const outcome = oauthPage.applyRotateSecretOutcome({
    currentNotice: {
      clientId: 'legacy-client',
      secret: 'legacy-secret',
      source: 'create',
    },
    result: {
      client: existingClient,
    },
  });

  assert.deepEqual(outcome, {
    secretNotice: null,
    toast: {
      message: 'admin-web 已轮换，但后端未返回新的 client secret，请重新操作。',
      type: 'error',
    },
  });
});
