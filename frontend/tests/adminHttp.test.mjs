import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

async function importBundledTs(relativePath) {
  const fullPath = path.resolve(relativePath);
  const outDir = await mkdtemp(path.join(tmpdir(), 'goauth-admin-http-'));
  const outFile = path.join(outDir, path.basename(relativePath).replace(/\.ts$/, '.cjs'));
  await build({
    entryPoints: [fullPath],
    outfile: outFile,
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'es2022',
  });
  return import(pathToFileURL(outFile).href);
}

function memoryStorage(initial = {}) {
  const values = new Map(Object.entries(initial));
  return {
    getItem: (key) => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
    dump: () => Object.fromEntries(values.entries()),
  };
}

function ok(config, data = { success: true, data: {} }) {
  return Promise.resolve({
    data,
    status: 200,
    statusText: 'OK',
    headers: {},
    config,
  });
}

function unauthorized(config) {
  return Promise.reject({
    config,
    response: {
      status: 401,
      data: { error: 'expired' },
    },
  });
}

const { createAdminHttpClient } = await importBundledTs('src/api/adminHttp.ts');

test('admin client refreshes tokens and retries the original request on 401', async () => {
  const storage = memoryStorage({
    access_token: 'old-access',
    refresh_token: 'old-refresh',
  });
  const calls = [];
  const client = createAdminHttpClient({
    baseURL: 'http://goauth.test/v1',
    storage,
    onExpired: () => assert.fail('should not redirect when refresh succeeds'),
    adapter: async (config) => {
      calls.push({
        url: config.url,
        auth: config.headers?.Authorization,
        data: config.data,
      });
      if (config.url === '/auth/refresh') {
        assert.equal(JSON.parse(config.data).refresh_token, 'old-refresh');
        return ok(config, {
          success: true,
          data: {
            access_token: 'new-access',
            refresh_token: 'new-refresh',
          },
        });
      }
      if (config.url === '/admin/users') {
        return config.headers?.Authorization === 'Bearer new-access'
          ? ok(config, { success: true, data: { users: [] } })
          : unauthorized(config);
      }
      throw new Error(`unexpected request ${config.url}`);
    },
  });

  const response = await client.get('/admin/users');

  assert.deepEqual(response.data, { success: true, data: { users: [] } });
  assert.deepEqual(storage.dump(), {
    access_token: 'new-access',
    refresh_token: 'new-refresh',
  });
  assert.deepEqual(calls.map(call => call.url), ['/admin/users', '/auth/refresh', '/admin/users']);
  assert.equal(calls[0].auth, 'Bearer old-access');
  assert.equal(calls[2].auth, 'Bearer new-access');
});

test('admin client clears tokens and redirects only when refresh fails', async () => {
  const storage = memoryStorage({
    access_token: 'old-access',
    refresh_token: 'bad-refresh',
  });
  let expiredCount = 0;
  const client = createAdminHttpClient({
    baseURL: 'http://goauth.test/v1',
    storage,
    onExpired: () => { expiredCount += 1; },
    adapter: async (config) => {
      if (config.url === '/auth/refresh') {
        return unauthorized(config);
      }
      return unauthorized(config);
    },
  });

  await assert.rejects(() => client.get('/admin/users'), /登录已过期/);

  assert.equal(expiredCount, 1);
  assert.deepEqual(storage.dump(), {});
});

test('admin client coalesces concurrent 401 refresh attempts', async () => {
  const storage = memoryStorage({
    access_token: 'old-access',
    refresh_token: 'old-refresh',
  });
  let refreshCount = 0;
  let releaseRefresh;
  const refreshGate = new Promise((resolve) => { releaseRefresh = resolve; });
  const client = createAdminHttpClient({
    baseURL: 'http://goauth.test/v1',
    storage,
    adapter: async (config) => {
      if (config.url === '/auth/refresh') {
        refreshCount += 1;
        await refreshGate;
        return ok(config, {
          success: true,
          data: {
            access_token: 'new-access',
            refresh_token: 'new-refresh',
          },
        });
      }
      if (config.headers?.Authorization === 'Bearer new-access') {
        return ok(config, { success: true, data: { ok: true } });
      }
      return unauthorized(config);
    },
  });

  const first = client.get('/admin/users');
  const second = client.get('/admin/sessions');
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(refreshCount, 1);
  releaseRefresh();

  const responses = await Promise.all([first, second]);

  assert.equal(refreshCount, 1);
  assert.deepEqual(responses.map(response => response.data.data), [{ ok: true }, { ok: true }]);
});
