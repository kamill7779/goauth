import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { mkdir, mkdtemp } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

async function importBrandMark(relativePath) {
  const fullPath = path.resolve(relativePath);
  const cacheRoot = path.resolve('node_modules/.cache');
  await mkdir(cacheRoot, { recursive: true });
  const outDir = await mkdtemp(path.join(cacheRoot, 'goauth-brand-mark-'));
  const outFile = path.join(outDir, 'brand-mark.cjs');

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

const brandMarkModule = await importBrandMark('src/components/BrandMark.tsx');
const BrandMark = brandMarkModule.default?.default ?? brandMarkModule.default;

test('BrandMark external icon does not send callback URL as referrer', () => {
  const html = renderToStaticMarkup(React.createElement(BrandMark, {
    brand: {
      name: 'Acme ID',
      tagline: 'Secure workforce access',
      icon_text: 'A',
      icon_url: 'https://cdn.example.com/acme.svg',
    },
  }));

  assert.match(html, /referrerPolicy="no-referrer"/);
});
