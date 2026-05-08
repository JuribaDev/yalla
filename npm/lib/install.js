'use strict';

// Download, verify, and unpack the matching native yalla binary from a
// GitHub Release. The wrapper is intentionally dependency-free: only Node
// core APIs are used so `npm install` does not pull a transitive surface.

const fs = require('fs');
const fsp = require('fs/promises');
const os = require('os');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { detect, checksumName, parseChecksum } = require('./platform');

const DEFAULT_REPO = 'JuribaDev/yalla';

function repoSlug() {
  return process.env.YALLA_REPO || DEFAULT_REPO;
}

function releaseBase() {
  if (process.env.YALLA_RELEASE_BASE) return process.env.YALLA_RELEASE_BASE;
  return `https://github.com/${repoSlug()}/releases/download`;
}

function packageVersion() {
  if (process.env.YALLA_VERSION) return process.env.YALLA_VERSION.replace(/^v/, '');
  // Resolved lazily so the install script loads even when package.json was
  // generated outside this directory (e.g. during snapshot smoke tests).
  const pkg = require('../package.json');
  return String(pkg.version || '').replace(/^v/, '');
}

function installRoot() {
  return path.resolve(__dirname, '..', 'binaries');
}

function binaryPath(plat = detect(process.platform, process.arch)) {
  return path.join(installRoot(), plat.binName);
}

async function exists(p) {
  try {
    await fsp.access(p, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function get(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      { headers: { 'user-agent': 'yalla-cli-npm-wrapper' } },
      (res) => {
        const code = res.statusCode || 0;
        if (code >= 300 && code < 400 && res.headers.location) {
          if (redirects >= 5) {
            res.resume();
            return reject(new Error(`too many redirects fetching ${url}`));
          }
          res.resume();
          return resolve(get(res.headers.location, redirects + 1));
        }
        if (code !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${code} fetching ${url}`));
        }
        resolve(res);
      },
    );
    req.on('error', reject);
    req.setTimeout(60_000, () => {
      req.destroy(new Error(`timeout fetching ${url}`));
    });
  });
}

async function fetchText(url) {
  const res = await get(url);
  return await new Promise((resolve, reject) => {
    const chunks = [];
    res.on('data', (c) => chunks.push(c));
    res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    res.on('error', reject);
  });
}

async function downloadFile(url, dest) {
  const res = await get(url);
  await new Promise((resolve, reject) => {
    const out = fs.createWriteStream(dest);
    res.pipe(out);
    res.on('error', reject);
    out.on('finish', () => out.close((err) => (err ? reject(err) : resolve())));
    out.on('error', reject);
  });
}

function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    fs.createReadStream(filePath)
      .on('data', (chunk) => hash.update(chunk))
      .on('end', () => resolve(hash.digest('hex')))
      .on('error', reject);
  });
}

function extractArchive(archivePath, dest, plat) {
  // Both unix tar and Windows tar (>= Win 10 1803) accept `tar -xf`. zip
  // archives are handled identically because tar.exe transparently invokes
  // the bsdtar zip handler. We fall back to `Expand-Archive` on Windows if
  // tar.exe is missing.
  const tar = spawnSync('tar', ['-xf', archivePath, '-C', dest], {
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  if (tar.status === 0) return;
  if (plat.ext === '.zip') {
    const ps = spawnSync(
      'powershell',
      ['-NoProfile', '-Command', `Expand-Archive -Path '${archivePath}' -DestinationPath '${dest}' -Force`],
      { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true },
    );
    if (ps.status === 0) return;
    throw new Error(
      `failed to extract ${archivePath}: tar exit=${tar.status}, powershell exit=${ps.status}`,
    );
  }
  throw new Error(`failed to extract ${archivePath}: tar exit=${tar.status}`);
}

async function ensureBinary(opts = {}) {
  const plat = opts.platform || detect(process.platform, process.arch);
  const target = opts.binaryPath || binaryPath(plat);
  if (await exists(target)) return target;

  const version = (opts.version || packageVersion()).replace(/^v/, '');
  if (!version || version === '0.0.0-dev') {
    throw new Error(
      'cannot resolve a release version — set YALLA_VERSION or publish the wrapper with a stamped version',
    );
  }
  const base = opts.releaseBase || releaseBase();
  const archive = plat.archive(version);
  const archiveURL = `${base}/v${version}/${archive}`;
  const checksumURL = `${base}/v${version}/${checksumName(version)}`;

  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'yalla-cli-'));
  try {
    const archivePath = path.join(tmp, archive);
    await downloadFile(archiveURL, archivePath);
    const checksumsBody = await fetchText(checksumURL);
    const expected = parseChecksum(checksumsBody, archive);
    const got = await sha256File(archivePath);
    if (got !== expected) {
      throw new Error(
        `checksum mismatch for ${archive}: expected ${expected}, got ${got}`,
      );
    }
    await fsp.mkdir(installRoot(), { recursive: true });
    extractArchive(archivePath, installRoot(), plat);
    if (!(await exists(target))) {
      throw new Error(
        `archive ${archive} did not contain expected binary ${plat.binName}`,
      );
    }
    if (process.platform !== 'win32') {
      await fsp.chmod(target, 0o755);
    }
    return target;
  } finally {
    await fsp.rm(tmp, { recursive: true, force: true });
  }
}

module.exports = {
  ensureBinary,
  binaryPath,
  installRoot,
  packageVersion,
  releaseBase,
  // exported for tests
  parseChecksum,
};
