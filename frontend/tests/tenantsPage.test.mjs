import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

async function importBundledTsx(relativePath) {
  const fullPath = path.resolve(relativePath);
  const outDir = await mkdtemp(path.join(tmpdir(), 'goauth-tenants-page-'));
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

const tenantsPage = await importBundledTsx('src/pages/Admin/TenantsPage.tsx');

test('loadAssignableUsers reads every admin users page instead of truncating at the first 100 records', async () => {
  const calls = [];
  const users = await tenantsPage.loadAssignableUsers(async (params) => {
    calls.push(params);
    if (params.page === 1) {
      return {
        data: Array.from({ length: 100 }, (_, index) => ({ id: index + 1, username: `user-${index + 1}`, email: `user-${index + 1}@example.com` })),
        total: 101,
        page: 1,
        page_size: 100,
      };
    }
    return {
      data: [{ id: 101, username: 'user-101', email: 'user-101@example.com' }],
      total: 101,
      page: 2,
      page_size: 100,
    };
  });

  assert.equal(users.length, 101);
  assert.deepEqual(calls, [
    { page: 1, page_size: 100, sort: 'username_asc' },
    { page: 2, page_size: 100, sort: 'username_asc' },
  ]);
});
