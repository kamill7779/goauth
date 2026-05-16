import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

async function importBrandHead(relativePath) {
  const fullPath = path.resolve(relativePath);
  const outDir = await mkdtemp(path.join(tmpdir(), 'goauth-brand-head-'));
  const outFile = path.join(outDir, 'brand-head.cjs');

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

function fakeDocument(existingLink) {
  const links = existingLink ? [existingLink] : [];
  return {
    title: '',
    head: {
      appendChild(element) {
        links.push(element);
      },
    },
    createElement(tag) {
      assert.equal(tag, 'link');
      return fakeLink();
    },
    querySelector(selector) {
      if (selector === 'link[rel~="icon"][data-runtime-brand-icon="true"]') {
        return links.find(link => link.rel === 'icon' && link.attributes['data-runtime-brand-icon'] === 'true') ?? null;
      }
      if (selector === 'link[rel~="icon"]') {
        return links.find(link => link.rel === 'icon') ?? null;
      }
      return null;
    },
  };
}

function fakeLink() {
  return {
    rel: 'icon',
    href: '',
    type: '',
    referrerPolicy: '',
    attributes: {},
    setAttribute(name, value) {
      this.attributes[name] = value;
    },
    removeAttribute(name) {
      delete this.attributes[name];
      if (name === 'type') {
        this.type = '';
      }
    },
  };
}

const { applyBrandHead, brandIconDataURL } = await importBrandHead('src/utils/brandHead.ts');

test('applyBrandHead maps runtime brand to title and external favicon', () => {
  const link = fakeLink();
  const doc = fakeDocument(link);

  applyBrandHead({
    name: 'Acme ID',
    tagline: 'Secure workforce access',
    icon_text: 'A',
    icon_url: 'https://cdn.example.com/acme.svg',
  }, doc);

  assert.equal(doc.title, 'Acme ID');
  assert.equal(link.href, 'https://cdn.example.com/acme.svg');
  assert.equal(link.referrerPolicy, 'no-referrer');
  assert.equal(link.attributes['data-runtime-brand-icon'], 'true');
  assert.equal(link.type, '');
});

test('applyBrandHead generates readable fallback SVG favicon', () => {
  const link = fakeLink();
  const doc = fakeDocument(link);

  applyBrandHead({
    name: '生产认证',
    tagline: '',
    icon_text: '认',
    icon_url: '',
  }, doc);

  assert.equal(doc.title, '生产认证');
  assert.equal(link.type, 'image/svg+xml');
  assert.equal(link.referrerPolicy, 'no-referrer');
  assert.match(link.href, /^data:image\/svg\+xml,/);

  const svg = decodeURIComponent(link.href.replace('data:image/svg+xml,', ''));
  assert.match(svg, /fill="#111827"/);
  assert.match(svg, />认<\/text>/);
});

test('brandIconDataURL escapes brand labels', () => {
  const svg = decodeURIComponent(brandIconDataURL({
    name: 'A&B <ID>',
    tagline: '',
    icon_text: '<',
    icon_url: '',
  }).replace('data:image/svg+xml,', ''));

  assert.match(svg, /A&amp;B &lt;ID&gt;/);
  assert.match(svg, /&lt;<\/text>/);
});
