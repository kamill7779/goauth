import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { mkdir, mkdtemp } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

async function importSlider(relativePath) {
  const fullPath = path.resolve(relativePath);
  const cacheRoot = path.resolve('node_modules/.cache');
  await mkdir(cacheRoot, { recursive: true });
  const outDir = await mkdtemp(path.join(cacheRoot, 'goauth-slider-human-check-'));
  const outFile = path.join(outDir, 'slider-human-check.cjs');

  await build({
    entryPoints: [fullPath],
    outfile: outFile,
    bundle: true,
    external: ['react', 'react/jsx-runtime'],
    platform: 'node',
    format: 'cjs',
    target: 'es2022',
    jsx: 'automatic',
    plugins: [
      {
        name: 'stub-human-check-api',
        setup(buildApi) {
          buildApi.onResolve({ filter: /^..\/..\/api\/humanCheck$/ }, () => ({
            path: 'human-check-api-stub',
            namespace: 'human-check-api-stub',
          }));
          buildApi.onLoad({ filter: /.*/, namespace: 'human-check-api-stub' }, () => ({
            contents: `
              export async function getSliderChallenge() {
                return {
                  id: 'challenge-1',
                  nonce: 'nonce-1',
                  thumb_x: 0,
                  thumb_y: 32,
                  thumb_width: 42,
                  thumb_height: 42,
                  width: 320,
                  height: 160,
                  image: 'data:image/svg+xml;base64,a',
                  thumb: 'data:image/svg+xml;base64,b',
                };
              }
              export async function verifySliderChallenge() {
                return { token: 'human-proof', expires_at: '2026-06-28T12:00:00Z' };
              }
            `,
            loader: 'js',
          }));
        },
      },
    ],
  });

  return import(pathToFileURL(outFile).href);
}

const sliderModule = await importSlider('src/components/auth/SliderHumanCheck.tsx');
const SliderHumanCheck = sliderModule.default?.default ?? sliderModule.default;

test('displayOffsetToChallengeX maps rendered CSS pixels back to challenge coordinates', () => {
  assert.equal(sliderModule.displayOffsetToChallengeX(188, 376, 320), 160);
  assert.notEqual(sliderModule.displayOffsetToChallengeX(188, 376, 320), 188);
});

test('SliderHumanCheck renders an accessible verification control', () => {
  const html = renderToStaticMarkup(React.createElement(SliderHumanCheck, {
    enabled: true,
    token: '',
    onToken: () => undefined,
    onError: () => undefined,
  }));

  assert.match(html, /拖动完成安全验证/);
  assert.match(html, /role="slider"/);
  assert.match(html, /aria-valuemin="0"/);
  assert.match(html, /aria-valuemax="100"/);
});

test('SliderHumanCheck stays empty when disabled', () => {
  const html = renderToStaticMarkup(React.createElement(SliderHumanCheck, {
    enabled: false,
    token: '',
    onToken: () => undefined,
    onError: () => undefined,
  }));

  assert.equal(html, '');
});
