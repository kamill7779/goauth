import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

async function importBundledTs(relativePath) {
  const fullPath = path.resolve(relativePath);
  const outDir = await mkdtemp(path.join(tmpdir(), 'goauth-admin-api-'));
  const outFile = path.join(outDir, path.basename(relativePath).replace(/\.ts$/, '.cjs'));
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

const admin = await importBundledTs('src/api/admin.ts');

test('classifyAdminAccessError distinguishes unauthenticated, forbidden, and unavailable states', () => {
  assert.equal(admin.classifyAdminAccessError({ status: 401 }), 'unauthenticated');
  assert.equal(admin.classifyAdminAccessError({ status: 403 }), 'forbidden');
  assert.equal(admin.classifyAdminAccessError(new Error('network down')), 'unavailable');
});

test('normalizeOAuthClientSecretResponse returns normalized client and one-time secret', () => {
  const result = admin.normalizeOAuthClientSecretResponse({
    success: true,
    data: {
      client_id: 'admin-web',
      name: 'Admin Web',
      redirect_uris: ['https://admin.example.com/callback'],
      allowed_scopes: ['openid', 'profile', 'email'],
      status: 'active',
      auto_provision_members: true,
      updated_at: '2026-05-12T03:00:00Z',
      client_secret: 'rotated-secret',
    },
  });

  assert.deepEqual(result, {
    client: {
      client_id: 'admin-web',
      name: 'Admin Web',
      redirect_uris: ['https://admin.example.com/callback'],
      scopes: ['openid', 'profile', 'email'],
      status: 'active',
      auto_provision_members: true,
      last_rotated: '2026-05-12T03:00:00Z',
    },
    client_secret: 'rotated-secret',
  });
});

test('normalizeOAuthClientSecretResponse omits empty secret values', () => {
  const result = admin.normalizeOAuthClientSecretResponse({
    success: true,
    data: {
      client_id: 'admin-web',
      name: 'Admin Web',
      redirect_uris: ['https://admin.example.com/callback'],
      scopes: ['openid'],
      status: 'disabled',
      auto_provision_members: false,
      updated_at: '2026-05-12T03:00:00Z',
      client_secret: null,
    },
  });

  assert.equal(result.client_secret, undefined);
  assert.equal(result.client.status, 'disabled');
});
