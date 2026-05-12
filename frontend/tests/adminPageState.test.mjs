import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

async function importBundledTsx(relativePath, prefix) {
  const fullPath = path.resolve(relativePath);
  const outDir = await mkdtemp(path.join(tmpdir(), prefix));
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

const usersPage = await importBundledTsx('src/pages/Admin/UsersPage.tsx', 'goauth-users-page-');
const rolesPage = await importBundledTsx('src/pages/Admin/RolesPage.tsx', 'goauth-roles-page-');

test('planUserListRefreshAfterCreate avoids stale-page refetch when current page is not first page', () => {
  assert.deepEqual(usersPage.planUserListRefreshAfterCreate(1), {
    nextPage: 1,
    shouldFetchImmediately: true,
  });

  assert.deepEqual(usersPage.planUserListRefreshAfterCreate(3), {
    nextPage: 1,
    shouldFetchImmediately: false,
  });
});

test('summarizeRolesPageLoad clears stale error after a fully successful retry', () => {
  const state = rolesPage.summarizeRolesPageLoad({
    rolesResult: {
      status: 'fulfilled',
      value: [{ id: 1, name: 'Root' }],
    },
    permissionsResult: {
      status: 'fulfilled',
      value: [{ id: 10, resource: 'users', action: 'read' }],
    },
    tenantsResult: {
      status: 'fulfilled',
      value: {
        data: [{ id: 99, name: 'System' }],
      },
    },
    currentTenantId: '',
  });

  assert.deepEqual(state, {
    roles: [{ id: 1, name: 'Root' }],
    permissions: [{ id: 10, resource: 'users', action: 'read' }],
    tenants: [{ id: 99, name: 'System' }],
    error: '',
    nextTenantId: '99',
  });
});

test('summarizeRolesPageLoad preserves the first load failure message when a dependency still fails', () => {
  const state = rolesPage.summarizeRolesPageLoad({
    rolesResult: {
      status: 'fulfilled',
      value: [],
    },
    permissionsResult: {
      status: 'rejected',
      reason: new Error('boom'),
    },
    tenantsResult: {
      status: 'fulfilled',
      value: {
        data: [{ id: 7, name: 'Tenant A' }],
      },
    },
    currentTenantId: '7',
  });

  assert.equal(state.error, 'boom');
  assert.equal(state.nextTenantId, '7');
});
