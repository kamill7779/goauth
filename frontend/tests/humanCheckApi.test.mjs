import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

async function importHumanCheckModule(relativePath) {
  const fullPath = path.resolve(relativePath);
  const outDir = await mkdtemp(path.join(tmpdir(), 'goauth-human-check-'));
  const outFile = path.join(outDir, 'human-check.cjs');

  await build({
    entryPoints: [fullPath],
    outfile: outFile,
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'es2022',
    plugins: [
      {
        name: 'stub-client',
        setup(buildApi) {
          buildApi.onResolve({ filter: /^\.\/client$/ }, () => ({
            path: 'client-stub',
            namespace: 'client-stub',
          }));
          buildApi.onLoad({ filter: /.*/, namespace: 'client-stub' }, () => ({
            contents: `
              export async function apiGet(path) {
                globalThis.__humanCheckCalls.push({ method: 'get', path });
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

              export async function apiPost(path, data) {
                globalThis.__humanCheckCalls.push({ method: 'post', path, data });
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

globalThis.__humanCheckCalls = [];

const { getSliderChallenge, verifySliderChallenge } = await importHumanCheckModule('src/api/humanCheck.ts');

test('human check API uses auth slider endpoints', async () => {
  globalThis.__humanCheckCalls.length = 0;

  const challenge = await getSliderChallenge();
  const token = await verifySliderChallenge({
    challenge_id: challenge.id,
    nonce: challenge.nonce,
    x: 120,
    y: 32,
    elapsed_ms: 900,
    track: [
      { x: 0, y: 32, t: 0 },
      { x: 120, y: 32, t: 900 },
    ],
  });

  assert.equal(challenge.id, 'challenge-1');
  assert.equal(token.token, 'human-proof');
  assert.deepEqual(globalThis.__humanCheckCalls, [
    { method: 'get', path: '/human-check/slider' },
    {
      method: 'post',
      path: '/human-check/slider/verify',
      data: {
        challenge_id: 'challenge-1',
        nonce: 'nonce-1',
        x: 120,
        y: 32,
        elapsed_ms: 900,
        track: [
          { x: 0, y: 32, t: 0 },
          { x: 120, y: 32, t: 900 },
        ],
      },
    },
  ]);
});
