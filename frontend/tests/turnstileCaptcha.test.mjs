import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { mkdir, mkdtemp } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

async function importTurnstileCaptcha(relativePath) {
  const fullPath = path.resolve(relativePath);
  const cacheRoot = path.resolve('node_modules/.cache');
  await mkdir(cacheRoot, { recursive: true });
  const outDir = await mkdtemp(path.join(cacheRoot, 'goauth-turnstile-captcha-'));
  const outFile = path.join(outDir, 'turnstile-captcha.cjs');

  await build({
    entryPoints: [fullPath],
    outfile: outFile,
    bundle: true,
    external: ['react', 'react/jsx-runtime'],
    platform: 'node',
    format: 'cjs',
    target: 'es2022',
    jsx: 'automatic',
  });

  return import(pathToFileURL(outFile).href);
}

const turnstileModule = await importTurnstileCaptcha('src/components/auth/TurnstileCaptcha.tsx');
const { buildTurnstileRenderOptions } = turnstileModule;
const TurnstileCaptcha = turnstileModule.default?.default ?? turnstileModule.default;

test('Turnstile render options use execute mode without invalid invisible size', () => {
  const options = buildTurnstileRenderOptions({
    siteKey: 'site-key',
    onSuccess: () => undefined,
    onError: () => undefined,
    onExpired: () => undefined,
  });

  assert.equal(options.sitekey, 'site-key');
  assert.equal(options.execution, 'execute');
  assert.equal(options.appearance, 'interaction-only');
  assert.equal(Object.hasOwn(options, 'size'), false);
});

test('Turnstile widget renders as an inline auth-card slot instead of a page-bottom float', () => {
  const html = renderToStaticMarkup(React.createElement(TurnstileCaptcha, {
    config: {
      issuer_url: 'https://identity.example.com',
      brand: { name: 'GoAuth', tagline: '', icon_text: 'G', icon_url: '' },
      registration: { mode: 'open' },
      local_login: { enabled: true },
      captcha: { provider: 'turnstile', site_key: 'site-key', actions: ['login'] },
      external_providers: [],
      password_policy: {
        min_length: 8,
        require_uppercase: false,
        require_lowercase: false,
        require_digit: true,
        require_special: false,
      },
      mailer: { provider: 'console' },
    },
  }));

  assert.match(html, /class="goauth-captcha-slot"/);
  assert.doesNotMatch(html, /position:\s*fixed/);
  assert.doesNotMatch(html, /bottom:/);
});
