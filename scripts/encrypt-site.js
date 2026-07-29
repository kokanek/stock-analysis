#!/usr/bin/env node
'use strict';
/**
 * encrypt-site.js — turn a plaintext static site into password-gated pages.
 *
 * Each HTML file is encrypted with AES-256-GCM under a key derived from your
 * passphrase via PBKDF2-SHA256. The output is a self-contained HTML file that
 * ships only ciphertext plus a small WebCrypto decryptor: the browser asks for
 * the passphrase, derives the key locally, decrypts, and writes the real
 * document. Nothing is sent to a server, so it works on GitHub Pages, Netlify,
 * or any dumb static host.
 *
 * Local stylesheets referenced with <link rel="stylesheet"> are inlined before
 * encryption, so no plaintext CSS is left sitting next to the locked pages.
 *
 *   node scripts/encrypt-site.js --key 'your passphrase'
 *   node scripts/encrypt-site.js            # prompts for the passphrase
 *
 * SECURITY MODEL — read this. The ciphertext is public and the passphrase is
 * shared by everyone who can read the site, so this stops casual readers and
 * search-engine indexing, not a determined attacker with your ciphertext and a
 * GPU. Use a long, random passphrase; PBKDF2 iterations only buy so much.
 */

const fs = require('fs');
const path = require('path');
const { webcrypto } = require('node:crypto');

const subtle = webcrypto.subtle;
const MARKER = '<!-- encrypted-site-lock v1 -->';
const DEFAULT_ITERATIONS = 600000; // OWASP guidance for PBKDF2-SHA256

// ───────────────────────────── args ─────────────────────────────────────────
function parseArgs(argv) {
  const opts = {
    in: 'site-src',
    out: 'docs',
    key: process.env.SITE_KEY || null,
    title: 'Protected',
    hint: '',
    iterations: DEFAULT_ITERATIONS,
    deleteOriginals: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) fail(`Missing value for ${a}`);
      return v;
    };
    switch (a) {
      case '--in': case '-i': opts.in = next(); break;
      case '--out': case '-o': opts.out = next(); break;
      case '--key': case '-k': opts.key = next(); break;
      case '--title': opts.title = next(); break;
      case '--hint': opts.hint = next(); break;
      case '--iterations': opts.iterations = parseInt(next(), 10); break;
      case '--delete-originals': opts.deleteOriginals = true; break;
      case '--help': case '-h': usage(); process.exit(0);
      default: fail(`Unknown argument: ${a}`);
    }
  }
  if (!Number.isInteger(opts.iterations) || opts.iterations < 10000) {
    fail('--iterations must be an integer >= 10000');
  }
  return opts;
}

function usage() {
  console.log(`
encrypt-site.js — password-gate a static HTML site for public hosting

  --in <dir>            plaintext source directory      (default: site-src)
  --out <dir>           encrypted output directory      (default: docs)
  --key, -k <phrase>    passphrase; also read from $SITE_KEY, else prompted
  --title <text>        <title> shown on the lock screen (default: Protected)
  --hint <text>         optional hint shown under the passphrase box
  --iterations <n>      PBKDF2 iterations               (default: ${DEFAULT_ITERATIONS})
  --delete-originals    delete the plaintext sources after a verified encrypt
  --help, -h            this message

Passing --key puts the passphrase in your shell history. Prefer the prompt or
an environment variable.
`);
}

function fail(msg) {
  console.error(`error: ${msg}`);
  process.exit(1);
}

// ─────────────────────── hidden passphrase prompt ───────────────────────────
function promptHidden(query) {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    if (!stdin.isTTY) {
      reject(new Error('no TTY available — pass --key or set SITE_KEY'));
      return;
    }
    process.stdout.write(query);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let pw = '';
    const onData = (ch) => {
      if (ch === '\n' || ch === '\r' || ch === '\u0004') {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stdout.write('\n');
        resolve(pw);
      } else if (ch === '\u0003') {          // ctrl-c
        stdin.setRawMode(false);
        process.stdout.write('\n');
        process.exit(130);
      } else if (ch === '\u007f' || ch === '\b') {
        pw = pw.slice(0, -1);
      } else {
        pw += ch;
      }
    };
    stdin.on('data', onData);
  });
}

// ───────────────────────────── crypto ───────────────────────────────────────
const b64 = (buf) => Buffer.from(buf).toString('base64');

async function deriveKey(passphrase, salt, iterations, usages) {
  const material = await subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    usages);
}

async function encrypt(plaintext, passphrase, iterations) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, iterations, ['encrypt', 'decrypt']);
  const ct = await subtle.encrypt(
    { name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
  return { salt: b64(salt), iv: b64(iv), ct: b64(new Uint8Array(ct)), iterations };
}

/** Round-trip check so we never delete a source we cannot actually recover. */
async function verify(payload, passphrase, expected) {
  const salt = Buffer.from(payload.salt, 'base64');
  const iv = Buffer.from(payload.iv, 'base64');
  const key = await deriveKey(passphrase, salt, payload.iterations, ['decrypt']);
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv }, key, Buffer.from(payload.ct, 'base64'));
  if (new TextDecoder().decode(pt) !== expected) throw new Error('round-trip mismatch');
}

// ───────────────────────────── html prep ────────────────────────────────────
/** Inline local <link rel="stylesheet"> so no plaintext CSS ships alongside. */
function inlineStylesheets(html, htmlPath, srcRoot) {
  return html.replace(
    /<link\b[^>]*rel=["']stylesheet["'][^>]*>/gi,
    (tag) => {
      const m = tag.match(/href=["']([^"']+)["']/i);
      if (!m) return tag;
      const href = m[1];
      if (/^(https?:)?\/\//i.test(href) || href.startsWith('data:')) return tag;
      const cssPath = path.resolve(path.dirname(htmlPath), href.split(/[?#]/)[0]);
      if (!cssPath.startsWith(path.resolve(srcRoot)) || !fs.existsSync(cssPath)) {
        console.warn(`  ! stylesheet not found, leaving as-is: ${href}`);
        return tag;
      }
      const css = fs.readFileSync(cssPath, 'utf8');
      return `<style>\n${css}\n</style>`;
    });
}

function collectHtml(dir, root = dir, acc = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) collectHtml(full, root, acc);
    else if (/\.html?$/i.test(entry.name)) acc.push(path.relative(root, full));
  }
  return acc;
}

// ───────────────────────────── lock page ────────────────────────────────────
function lockPage({ payload, title, hint }) {
  const hintHtml = hint
    ? `<p class="hint">${hint.replace(/[<>&]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]))}</p>`
    : '';
  return `<!DOCTYPE html>
${MARKER}
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${title}</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #0d1117; color: #e6edf3; padding: 1.5rem;
    font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  .box {
    width: 100%; max-width: 24rem; background: #161b22;
    border: 1px solid #2d333b; border-radius: 12px; padding: 1.8rem;
  }
  h1 { font-size: 1.15rem; margin-bottom: 0.4rem; }
  p.sub { color: #9da7b3; font-size: 0.9rem; margin-bottom: 1.2rem; }
  label { display: block; font-size: 0.8rem; color: #9da7b3; margin-bottom: 0.35rem; }
  input {
    width: 100%; padding: 0.6rem 0.75rem; border-radius: 8px;
    border: 1px solid #2d333b; background: #0d1117; color: #e6edf3;
    font-size: 1rem; font-family: inherit;
  }
  input:focus { outline: none; border-color: #4aa3ff; }
  button {
    width: 100%; margin-top: 0.9rem; padding: 0.6rem; border: none; border-radius: 8px;
    background: #4aa3ff; color: #0d1117; font-size: 0.95rem; font-weight: 600;
    font-family: inherit; cursor: pointer;
  }
  button:disabled { opacity: 0.6; cursor: default; }
  .msg { margin-top: 0.8rem; font-size: 0.85rem; min-height: 1.2rem; }
  .msg.err { color: #ff6b6b; }
  .msg.busy { color: #9da7b3; }
  .hint { margin-top: 0.9rem; font-size: 0.8rem; color: #9da7b3; }
</style>
</head>
<body>
<div class="box">
  <h1>${title}</h1>
  <p class="sub">This page is encrypted. Enter the passphrase to view it.</p>
  <form id="f" autocomplete="off">
    <label for="pw">Passphrase</label>
    <input id="pw" type="password" autofocus autocomplete="current-password">
    <button id="go" type="submit">Unlock</button>
  </form>
  <div class="msg" id="msg"></div>
  ${hintHtml}
</div>
<script>
(function () {
  var P = ${JSON.stringify(payload)};
  var STORE = 'encrypted-site-key';
  var f = document.getElementById('f');
  var pw = document.getElementById('pw');
  var go = document.getElementById('go');
  var msg = document.getElementById('msg');

  function say(text, cls) { msg.textContent = text; msg.className = 'msg' + (cls ? ' ' + cls : ''); }

  function bytes(b64) {
    var bin = atob(b64), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  if (!window.crypto || !window.crypto.subtle) {
    say('WebCrypto unavailable. Open this page over https:// or http://localhost, not file://.', 'err');
    go.disabled = true;
    return;
  }

  async function decrypt(phrase) {
    var material = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(phrase), 'PBKDF2', false, ['deriveKey']);
    var key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: bytes(P.salt), iterations: P.iterations, hash: 'SHA-256' },
      material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    var plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: bytes(P.iv) }, key, bytes(P.ct));
    return new TextDecoder().decode(plain);
  }

  function render(html) {
    document.open();
    document.write(html);
    document.close();
  }

  async function attempt(phrase, fromStore) {
    if (!phrase) { say('Enter the passphrase.', 'err'); return; }
    go.disabled = true;
    say('Decrypting\\u2026', 'busy');
    try {
      var html = await decrypt(phrase);
      try { sessionStorage.setItem(STORE, phrase); } catch (e) {}
      render(html);
    } catch (e) {
      go.disabled = false;
      if (fromStore) {
        try { sessionStorage.removeItem(STORE); } catch (e2) {}
        say('');
      } else {
        say('Wrong passphrase.', 'err');
        pw.select();
      }
    }
  }

  f.addEventListener('submit', function (e) { e.preventDefault(); attempt(pw.value, false); });

  // Unlock once per tab: sibling pages reuse the passphrase from sessionStorage.
  var saved = null;
  try { saved = sessionStorage.getItem(STORE); } catch (e) {}
  if (saved) attempt(saved, true);
})();
</script>
</body>
</html>
`;
}

// ───────────────────────────── main ─────────────────────────────────────────
(async function main() {
  const opts = parseArgs(process.argv);

  const srcRoot = path.resolve(opts.in);
  const outRoot = path.resolve(opts.out);
  if (!fs.existsSync(srcRoot) || !fs.statSync(srcRoot).isDirectory()) {
    fail(`input directory not found: ${opts.in}`);
  }

  const files = collectHtml(srcRoot);
  if (files.length === 0) fail(`no .html files found in ${opts.in}`);

  // Refuse to double-encrypt: a locked page re-encrypted becomes unreadable.
  for (const rel of files) {
    if (fs.readFileSync(path.join(srcRoot, rel), 'utf8').includes(MARKER)) {
      fail(`${rel} is already an encrypted lock page. Encrypt from plaintext sources, not from ${opts.out}.`);
    }
  }

  let passphrase = opts.key;
  if (!passphrase) {
    passphrase = await promptHidden('Passphrase: ');
    const again = await promptHidden('Confirm:    ');
    if (passphrase !== again) fail('passphrases did not match');
  }
  if (!passphrase) fail('empty passphrase');
  if (passphrase.length < 8) {
    console.warn('warning: short passphrase — the ciphertext is public and brute-forceable offline');
  }

  console.log(`\nEncrypting ${files.length} page(s): ${opts.in} -> ${opts.out}`);
  console.log(`PBKDF2-SHA256, ${opts.iterations.toLocaleString()} iterations, AES-256-GCM\n`);

  fs.mkdirSync(outRoot, { recursive: true });

  for (const rel of files) {
    const srcPath = path.join(srcRoot, rel);
    const raw = fs.readFileSync(srcPath, 'utf8');
    const prepared = inlineStylesheets(raw, srcPath, srcRoot);

    const payload = await encrypt(prepared, passphrase, opts.iterations);
    await verify(payload, passphrase, prepared);   // never ship what we can't decrypt

    const outPath = path.join(outRoot, rel);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, lockPage({ payload, title: opts.title, hint: opts.hint }));

    const kb = (Buffer.byteLength(prepared) / 1024).toFixed(1);
    console.log(`  ok  ${rel}  (${kb} kB plaintext -> encrypted, verified)`);
  }

  if (opts.deleteOriginals) {
    if (srcRoot === outRoot) fail('refusing to delete originals when --in and --out are the same directory');
    for (const rel of files) fs.unlinkSync(path.join(srcRoot, rel));
    // Inlined stylesheets are now embedded in the ciphertext; drop the plaintext copies.
    const stray = [];
    const sweep = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) sweep(full);
        else if (/\.css$/i.test(e.name)) { fs.unlinkSync(full); stray.push(path.relative(srcRoot, full)); }
      }
    };
    sweep(srcRoot);
    console.log(`\n  deleted ${files.length} plaintext page(s)${stray.length ? ` and ${stray.length} stylesheet(s)` : ''} from ${opts.in}`);
    console.log('  (recover them from git history if you need to edit and re-encrypt)');
  }

  console.log(`\nDone. Publish ${opts.out}/ — it contains ciphertext only.`);
  console.log('Test locally with a real HTTP origin (WebCrypto is blocked on file://):');
  console.log(`  npx --yes http-server ${opts.out} -p 8080   # then open http://localhost:8080\n`);
})().catch((e) => fail(e && e.message ? e.message : String(e)));
