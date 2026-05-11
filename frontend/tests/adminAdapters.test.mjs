import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { transform } from 'esbuild';

async function importTs(relativePath) {
  const fullPath = path.resolve(relativePath);
  const source = await readFile(fullPath, 'utf8');
  const { code } = await transform(source, {
    loader: 'ts',
    format: 'esm',
    target: 'es2022',
  });
  const outDir = await mkdtemp(path.join(tmpdir(), 'goauth-admin-adapters-'));
  const outFile = path.join(outDir, path.basename(relativePath).replace(/\.ts$/, '.mjs'));
  await writeFile(outFile, code);
  return import(pathToFileURL(outFile).href);
}

const adapters = await importTs('src/api/adminAdapters.ts');

test('asPaginated unwraps backend named collection payloads', () => {
  const payload = {
    success: true,
    data: {
      users: [{ id: 1, email: 'admin@example.com' }],
    },
  };

  assert.deepEqual(adapters.asPaginated(payload, 'users'), {
    data: [{ id: 1, email: 'admin@example.com' }],
    total: 1,
    page: 1,
    page_size: 1,
  });
});

test('asCollection unwraps backend array fields', () => {
  assert.deepEqual(
    adapters.asCollection({ success: true, data: { roles: [{ id: 10, name: 'Root' }] } }, 'roles'),
    [{ id: 10, name: 'Root' }],
  );
});

test('normalizeOAuthClient maps backend allowed_scopes into frontend scopes', () => {
  assert.deepEqual(
    adapters.normalizeOAuthClient({
      client_id: 'bbs-go-web',
      name: 'BBS Go',
      redirect_uris: ['https://forum.example.com/callback'],
      allowed_scopes: ['openid', 'profile', 'email'],
      status: 'disabled',
      auto_provision_members: true,
      updated_at: '2026-05-11T10:00:00Z',
    }),
    {
      client_id: 'bbs-go-web',
      name: 'BBS Go',
      redirect_uris: ['https://forum.example.com/callback'],
      scopes: ['openid', 'profile', 'email'],
      status: 'disabled',
      auto_provision_members: true,
      last_rotated: '2026-05-11T10:00:00Z',
    },
  );
});

test('role and member mutation payloads match GoAuth backend contracts', () => {
  assert.deepEqual(adapters.rolePermissionRequest(7), { permission_ids: [7] });
  assert.deepEqual(adapters.memberRoleRequest(9), { role_ids: [9] });
});
