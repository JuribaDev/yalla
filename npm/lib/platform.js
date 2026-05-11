'use strict';

// Map Node.js platform/arch tuples to GoReleaser asset coordinates.
// Keep this list in sync with `.goreleaser.yaml > builds[0].goos / goarch`.

const OS_MAP = Object.freeze({
  darwin: 'darwin',
  linux: 'linux',
  win32: 'windows',
});

const ARCH_MAP = Object.freeze({
  x64: 'amd64',
  arm64: 'arm64',
});

/**
 * Resolve the release asset descriptor for a Node.js platform/arch pair.
 *
 * @param {string} platform process.platform value
 * @param {string} arch process.arch value
 * @returns {{os:string, arch:string, ext:string, binName:string, archive:(version:string)=>string}}
 */
function detect(platform, arch) {
  const os = OS_MAP[platform];
  if (!os) {
    throw new Error(
      `unsupported platform "${platform}" — yalla ships binaries for darwin, linux, windows`,
    );
  }
  const goarch = ARCH_MAP[arch];
  if (!goarch) {
    throw new Error(
      `unsupported architecture "${arch}" — yalla ships binaries for amd64 (x64), arm64`,
    );
  }
  const ext = os === 'windows' ? '.zip' : '.tar.gz';
  const binName = os === 'windows' ? 'yalla.exe' : 'yalla';
  return {
    os,
    arch: goarch,
    ext,
    binName,
    archive: (version) => `yalla_${version}_${os}_${goarch}${ext}`,
  };
}

/**
 * @param {string} version semantic version (no leading "v")
 */
function checksumName(version) {
  return `yalla_${version}_checksums.txt`;
}

/**
 * Find the SHA256 hex string for a given filename inside a checksums.txt blob
 * produced by GoReleaser. The file format is "<hex>  <filename>" per line.
 *
 * @param {string} text checksums file body
 * @param {string} filename archive filename to look up
 * @returns {string} 64 char hex
 */
function parseChecksum(text, filename) {
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const match = trimmed.match(/^([0-9a-fA-F]{64})\s+\*?(.+)$/);
    if (!match) continue;
    if (match[2] === filename) return match[1].toLowerCase();
  }
  throw new Error(`checksum for ${filename} not found in checksums.txt`);
}

module.exports = { detect, checksumName, parseChecksum, OS_MAP, ARCH_MAP };
