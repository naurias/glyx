import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const shared = [
  'background.js',
  'compat.js',
  'content.js',
  'lib.js',
  'popup.html',
  'popup.js',
  'passkey.html',
  'passkey.js',
  'firefox-passkey.html',
  'firefox-passkey.js'
];
const manifests = {
  chromium: 'manifest.chromium.json',
  firefox: 'manifest.firefox.json'
};

const args = process.argv.slice(2);
const check = args.includes('--check');
const requested = args.filter((argument) => !argument.startsWith('-'));
const targets =
  requested.length === 0 || requested.includes('all')
    ? Object.keys(manifests)
    : requested;

for (const target of targets) {
  if (!manifests[target]) {
    console.error(`unknown browser ${target}; use ${Object.keys(manifests).join(', ')}`);
    process.exit(2);
  }
}

let failed = false;

async function stageFile(destination, contents) {
  if (check) {
    const current = existsSync(destination)
      ? await readFile(destination, 'utf8')
      : null;
    if (current !== contents) {
      console.error(`out of date: ${path.relative(root, destination)}`);
      failed = true;
    }
    return;
  }
  await writeFile(destination, contents);
}

for (const target of targets) {
  const directory = path.join(root, 'dist', target);
  if (!check) await mkdir(directory, { recursive: true });
  for (const file of shared) {
    const contents = await readFile(path.join(root, file), 'utf8');
    await stageFile(path.join(directory, file), contents);
  }
  const manifest = JSON.parse(
    await readFile(path.join(root, manifests[target]), 'utf8')
  );
  await stageFile(
    path.join(directory, 'manifest.json'),
    `${JSON.stringify(manifest, null, 2)}\n`
  );
  if (!check) console.log(`staged ${path.relative(root, directory)}`);
}

if (check) {
  if (failed) {
    console.error('run `node apps/extension/build.mjs all` to refresh dist');
    process.exit(1);
  }
  console.log('extension dist is up to date');
}
