import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

async function importCallbackModule(relativePath) {
  const fullPath = path.resolve(relativePath);
  const outDir = await mkdtemp(path.join(tmpdir(), 'goauth-external-callback-'));
  const outFile = path.join(outDir, 'external-callback.cjs');

  await build({
    entryPoints: [fullPath],
    outfile: outFile,
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'es2022',
    define: {
      'import.meta.env.VITE_API_BASE_URL': '"https://identity.example.com"',
      'import.meta.env.VITE_OIDC_ISSUER_URL': '"https://identity.example.com"',
    },
    plugins: [
      {
        name: 'stub-auth-api',
        setup(buildApi) {
          buildApi.onResolve({ filter: /^\.\.\/api\/auth$/ }, () => ({
            path: 'auth-stub',
            namespace: 'auth-stub',
          }));
          buildApi.onLoad({ filter: /.*/, namespace: 'auth-stub' }, () => ({
            contents: `export async function exchangeGitHubLogin() { throw new Error('not used in helper tests') }`,
            loader: 'js',
          }));
        },
      },
    ],
  });

  return import(pathToFileURL(outFile).href);
}

const callback = await importCallbackModule('src/pages/ExternalCallbackPage.tsx');

test('externalCallbackStateFromSearch reads provider and code', () => {
  assert.deepEqual(
    callback.externalCallbackStateFromSearch('?provider=github&code=exchange-code'),
    { provider: 'github', code: 'exchange-code' },
  );
});

test('externalCallbackStateFromLocation prefers fragment exchange credentials', () => {
  assert.deepEqual(
    callback.externalCallbackStateFromLocation('?provider=ignored&code=query-code', '#provider=github&code=fragment-code'),
    { provider: 'github', code: 'fragment-code' },
  );
});

test('storeExternalLoginTokens persists token pair', () => {
  const writes = [];
  const storage = {
    setItem: (key, value) => writes.push([key, value]),
  };

  callback.storeExternalLoginTokens(storage, {
    access_token: 'access-token',
    refresh_token: 'refresh-token',
    session_id: 'sid',
  });

  assert.deepEqual(writes, [
    ['access_token', 'access-token'],
    ['refresh_token', 'refresh-token'],
  ]);
});

test('externalCallbackURLWithoutExchangeCode strips exchange credentials', () => {
  assert.equal(
    callback.externalCallbackURLWithoutExchangeCode('https://console.example.com/external/callback?provider=github&code=one-time-code&theme=dark#done'),
    '/external/callback?theme=dark#done',
  );
  assert.equal(
    callback.externalCallbackURLWithoutExchangeCode('https://console.example.com/external/callback?theme=dark#provider=github&code=one-time-code&mode=oauth'),
    '/external/callback?theme=dark#mode=oauth',
  );
});

test('resolveExternalRedirect defaults to account center and rejects external URLs', () => {
  assert.equal(callback.resolveExternalRedirect('/oauth2/authorize?client_id=demo'), '/oauth2/authorize?client_id=demo');
  assert.equal(callback.resolveExternalRedirect('https://evil.example.com/callback'), '/account');
  assert.equal(callback.resolveExternalRedirect(''), '/account');
});

test('resolveExternalRedirect allows trusted cross-origin authorize return_to', () => {
  assert.equal(
    callback.resolveExternalRedirect('https://identity.example.com/oauth2/authorize?client_id=demo', {
      currentOrigin: 'https://console.example.com',
      apiBaseURL: 'https://identity.example.com',
    }),
    'https://identity.example.com/oauth2/authorize?client_id=demo',
  );
  assert.equal(
    callback.resolveExternalRedirect('https://identity.example.com/admin', {
      currentOrigin: 'https://console.example.com',
      apiBaseURL: 'https://identity.example.com',
    }),
    '/account',
  );
  assert.equal(
    callback.resolveExternalRedirect('https://api.example.com/oauth2/authorize?client_id=demo', {
      currentOrigin: 'https://console.example.com',
      apiBaseURL: 'https://api.example.com',
      issuerURL: 'https://identity.example.com',
    }),
    '/account',
  );
});
