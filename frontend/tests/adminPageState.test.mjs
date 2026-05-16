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
const settingsPage = await importBundledTsx('src/pages/Admin/SettingsPage.tsx', 'goauth-settings-page-');

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

test('buildRuntimeStatusGroups maps public config into read-only settings', () => {
  const groups = settingsPage.buildRuntimeStatusGroups({
    registration: { mode: 'invite_only' },
    local_login: { enabled: false },
    captcha: { provider: 'turnstile', site_key: 'site-key', actions: ['login', 'register'] },
    external_providers: [
      { slug: 'github', display_name: 'GitHub', start_url: '/v1/external/github/start' },
    ],
    password_policy: {
      min_length: 10,
      require_uppercase: true,
      require_lowercase: true,
      require_digit: true,
      require_special: false,
    },
    mailer: { provider: 'console' },
  });

  const flatItems = groups.flatMap(group => group.items);
  assert.equal(flatItems.find(item => item.label === '注册模式').value, '仅邀请');
  assert.equal(flatItems.find(item => item.label === '本地密码登录').value, '关闭');
  assert.equal(flatItems.find(item => item.label === 'GitHub 登录').value, '启用');
  assert.equal(flatItems.find(item => item.label === 'CAPTCHA').value, 'turnstile: login, register');
  assert.equal(flatItems.some(item => item.label.includes('MFA')), false);
  assert.equal(flatItems.every(item => item.readOnly), true);
});

test('runtimeStatusGroupsForLoadedConfig does not synthesize default runtime status before config loads', () => {
  assert.deepEqual(settingsPage.runtimeStatusGroupsForLoadedConfig(null), []);
});

test('buildRuntimeDiagnosticGroups maps admin runtime config risks into read-only diagnostics', () => {
  const groups = settingsPage.buildRuntimeDiagnosticGroups({
    environment: 'production',
    groups: [
      {
        key: 'tokens',
        items: [
          {
            key: 'JWT_PRIVATE_KEY_PATH',
            group: 'tokens',
            status: 'error',
            configured: false,
            required: true,
            secret: true,
            public_config: false,
            source: 'empty',
            message: 'persistent signing key is required in production',
          },
        ],
      },
      {
        key: 'captcha',
        items: [
          {
            key: 'CAPTCHA_SITE_KEY',
            group: 'captcha',
            status: 'ok',
            configured: true,
            required: true,
            secret: false,
            public_config: true,
            source: 'configured',
            message: 'configured',
          },
        ],
      },
    ],
  });

  assert.deepEqual(groups.map(group => group.section), ['tokens', 'captcha']);
  const flatItems = groups.flatMap(group => group.items);
  assert.equal(flatItems.find(item => item.label === 'JWT_PRIVATE_KEY_PATH').value, '错误');
  assert.equal(flatItems.find(item => item.label === 'JWT_PRIVATE_KEY_PATH').severity, 'error');
  assert.equal(flatItems.find(item => item.label === 'CAPTCHA_SITE_KEY').value, '正常');
  assert.equal(flatItems.every(item => item.readOnly), true);
});
