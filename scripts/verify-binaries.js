#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const BIN_DIR = path.join(ROOT, 'binaries');
const PKG = path.join(ROOT, 'package.json');

const version = (() => { try { return require(PKG).version; } catch (e) { console.error('Could not read package.json version:', e.message); process.exit(2); } })();

const expectedNames = [
  'vibe-guard-linux-x64',
  'vibe-guard-linux-arm64',
  'vibe-guard-macos-x64',
  'vibe-guard-macos-arm64',
  'vibe-guard-windows-x64.exe'
];

function sha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('error', reject);
    stream.on('data', (d) => hash.update(d));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

function execWithTimeout(cmd, args, cwd, timeoutMs) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd, shell: false, windowsHide: true });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const to = setTimeout(() => {
      timedOut = true;
      try { child.kill('SIGKILL'); } catch (e) {}
    }, timeoutMs);
    child.stdout && child.stdout.on('data', (b) => stdout += b.toString());
    child.stderr && child.stderr.on('data', (b) => stderr += b.toString());
    child.on('close', (code, signal) => {
      clearTimeout(to);
      resolve({ code, signal, stdout, stderr, timedOut });
    });
    child.on('error', (err) => {
      clearTimeout(to);
      resolve({ error: err.message, timedOut });
    });
  });
}

(async () => {
  let failed = false;
  console.log('Package version:', version);
  for (const name of expectedNames) {
    const p = path.join(BIN_DIR, name);
    if (!fs.existsSync(p)) {
      console.log('Missing binary (skipping):', name);
      continue;
    }

    try {
      const sum = await sha256(p);
      console.log(`Binary: ${name}  sha256: ${sum}`);
    } catch (e) {
      console.error('Failed to hash', name, e.message);
      failed = true;
      continue;
    }

    // Try running --version with a 5s timeout
    console.log('Running --version for', name);
    const res = await execWithTimeout(p, ['--version'], ROOT, 5000);
    if (res.timedOut) {
      console.error(name, 'timed out running --version (killed)');
      // Try fallback string scan
    } else if (res.error) {
      console.error(name, 'exec error:', res.error);
    } else if (res.stdout && res.stdout.includes(version)) {
      console.log(name, '--version output includes version');
      continue;
    } else if (res.stderr && res.stderr.includes(version)) {
      console.log(name, '--version stderr includes version');
      continue;
    } else if (typeof res.code === 'number' && res.code === 0 && (res.stdout || res.stderr)) {
      console.log(name, '--version returned exit 0 with output (not matching version)');
    } else {
      console.log(name, '--version did not print version. trying binary scan fallback.');
    }

    // Fallback: search raw bytes for version string
    try {
      const buf = fs.readFileSync(p);
      const bs = Buffer.from(version);
      if (buf.indexOf(bs) !== -1) {
        console.log(`${name} contains version string in binary`);
        continue;
      } else {
        console.error(`${name} DOES NOT contain version string in binary and --version check failed`);
        failed = true;
      }
    } catch (e) {
      console.error('Failed to read binary for scan', name, e.message);
      failed = true;
    }
  }

  if (failed) {
    console.error('\nOne or more binary checks failed');
    process.exit(1);
  }

  console.log('\nAll present binaries passed lightweight smoke checks');
  process.exit(0);
})();
