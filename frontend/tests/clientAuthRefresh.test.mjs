import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

async function importBundledTs(relativePath) {
  const fullPath = path.resolve(relativePath);
  const outDir = await mkdtemp(path.join(tmpdir(), 'goauth-client-refresh-'));
  const outFile = path.join(outDir, path.basename(relativePath).replace(/\.ts$/, '.cjs'));
  await build({
    entryPoints: [fullPath],
    outfile: outFile,
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'es2022',
    define: {
      'import.meta.env.VITE_API_BASE_URL': '""',
    },
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

function unauthorized(config, error = 'token has invalid claims: token is expired') {
  return Promise.reject({
    config,
    response: {
      status: 401,
      data: { error },
    },
  });
}

const { createApiHttpClients } = await importBundledTs('src/api/client.ts');

test('v1 client refreshes access token and retries protected request on 401', async () => {
  const storage = memoryStorage({
    access_token: 'old-access',
    refresh_token: 'old-refresh',
  });
  const calls = [];
  const { v1Client } = createApiHttpClients({
    apiBaseUrl: 'http://goauth.test',
    storage,
    onExpired: () => assert.fail('refresh should prevent expiration redirect'),
    adapter: async (config) => {
      calls.push({
        url: config.url,
        auth: config.headers?.Authorization,
        data: config.data,
      });
      if (config.url === '/refresh') {
        assert.equal(JSON.parse(config.data).refresh_token, 'old-refresh');
        return ok(config, {
          success: true,
          data: {
            access_token: 'new-access',
            refresh_token: 'new-refresh',
          },
        });
      }
      if (config.url === '/account/me') {
        return config.headers?.Authorization === 'Bearer new-access'
          ? ok(config, { success: true, data: { user: { id: 1 } } })
          : unauthorized(config);
      }
      throw new Error(`unexpected request ${config.url}`);
    },
  });

  const response = await v1Client.get('/account/me');

  assert.deepEqual(response.data, { success: true, data: { user: { id: 1 } } });
  assert.deepEqual(storage.dump(), {
    access_token: 'new-access',
    refresh_token: 'new-refresh',
  });
  assert.deepEqual(calls.map((call) => call.url), ['/account/me', '/refresh', '/account/me']);
  assert.equal(calls[0].auth, 'Bearer old-access');
  assert.equal(calls[2].auth, 'Bearer new-access');
});

test('public auth login 401 does not trigger token refresh', async () => {
  const storage = memoryStorage({
    access_token: 'old-access',
    refresh_token: 'old-refresh',
  });
  const calls = [];
  const { authClient } = createApiHttpClients({
    apiBaseUrl: 'http://goauth.test',
    storage,
    adapter: async (config) => {
      calls.push({
        url: config.url,
        auth: config.headers?.Authorization,
      });
      if (config.url === '/login') {
        return unauthorized(config, 'invalid credentials');
      }
      if (config.url === '/refresh') {
        assert.fail('login failures must not refresh tokens');
      }
      throw new Error(`unexpected request ${config.url}`);
    },
  });

  await assert.rejects(() => authClient.post('/login', { email: 'member@example.com', password: 'bad' }), /invalid credentials/);

  assert.deepEqual(calls, [
    { url: '/login', auth: undefined },
  ]);
  assert.deepEqual(storage.dump(), {
    access_token: 'old-access',
    refresh_token: 'old-refresh',
  });
});
