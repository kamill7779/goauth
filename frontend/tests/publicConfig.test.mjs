import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

async function importPublicConfigModule(relativePath) {
  const fullPath = path.resolve(relativePath);
  const outDir = await mkdtemp(path.join(tmpdir(), 'goauth-public-config-'));
  const outFile = path.join(outDir, 'public-config.cjs');

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

const { normalizePublicConfig, captchaEnabledForAction, humanCheckEnabledForAction } = await importPublicConfigModule('src/api/publicConfig.ts');

test('normalizePublicConfig fills safe defaults', () => {
  const cfg = normalizePublicConfig({});

  assert.equal(cfg.registration.mode, 'open');
  assert.equal(cfg.issuer_url, '');
  assert.equal(cfg.local_login.enabled, true);
  assert.deepEqual(cfg.external_providers, []);
  assert.equal(cfg.mailer.provider, 'console');
  assert.deepEqual(cfg.human_check, { provider: '', actions: [] });
  assert.deepEqual(cfg.brand, {
    name: 'GoAuth',
    tagline: '',
    icon_text: 'G',
    icon_url: '',
  });
});

test('normalizePublicConfig maps runtime branding', () => {
  const cfg = normalizePublicConfig({
    issuer_url: 'https://identity.example.com',
    brand: {
      name: 'Acme ID',
      tagline: 'Secure workforce access',
      icon_text: 'A',
      icon_url: 'https://cdn.example.com/acme.svg',
    },
  });

  assert.equal(cfg.issuer_url, 'https://identity.example.com');
  assert.equal(cfg.brand.name, 'Acme ID');
  assert.equal(cfg.brand.tagline, 'Secure workforce access');
  assert.equal(cfg.brand.icon_text, 'A');
  assert.equal(cfg.brand.icon_url, 'https://cdn.example.com/acme.svg');
});

test('captchaEnabledForAction follows runtime actions', () => {
  const cfg = normalizePublicConfig({
    captcha: {
      provider: 'turnstile',
      site_key: 'site-key',
      actions: ['Login', 'LOGIN'],
    },
  });

  assert.equal(captchaEnabledForAction(cfg, 'login'), true);
  assert.equal(captchaEnabledForAction(cfg, 'LOGIN'), true);
  assert.deepEqual(cfg.captcha.actions, ['login']);
  assert.equal(captchaEnabledForAction(cfg, 'register'), false);
});

test('humanCheckEnabledForAction follows runtime actions', () => {
  const cfg = normalizePublicConfig({
    human_check: {
      provider: 'slider',
      actions: ['Register', 'REGISTER'],
    },
  });

  assert.equal(humanCheckEnabledForAction(cfg, 'register'), true);
  assert.equal(humanCheckEnabledForAction(cfg, 'REGISTER'), true);
  assert.deepEqual(cfg.human_check.actions, ['register']);
  assert.equal(humanCheckEnabledForAction(cfg, 'login'), false);
});
