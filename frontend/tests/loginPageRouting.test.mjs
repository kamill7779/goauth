import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

async function importLoginPageModule(relativePath) {
  const fullPath = path.resolve(relativePath);
  const outDir = await mkdtemp(path.join(tmpdir(), 'goauth-login-page-'));
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

const loginPage = await importLoginPageModule('src/pages/LoginPage.tsx');

test('buildAuthRoutePath preserves return_to through reset-password navigation', () => {
  const nextPath = loginPage.buildAuthRoutePath('/reset-password', {
    email: 'member@example.com',
    returnTo: '/oauth2/authorize?client_id=demo-web&state=opaque-state',
  });
  const parsed = new URL(nextPath, 'http://goauth.test');

  assert.equal(parsed.pathname, '/reset-password');
  assert.equal(parsed.searchParams.get('email'), 'member@example.com');
  assert.equal(
    parsed.searchParams.get('return_to'),
    '/oauth2/authorize?client_id=demo-web&state=opaque-state',
  );
});

test('buildAuthRoutePath omits empty return_to', () => {
  const nextPath = loginPage.buildAuthRoutePath('/login', {
    returnTo: '',
  });
  const parsed = new URL(nextPath, 'http://goauth.test');

  assert.equal(parsed.pathname, '/login');
  assert.equal(parsed.searchParams.has('return_to'), false);
});
