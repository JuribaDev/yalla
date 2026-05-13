'use strict';

// Smoke tests for the npm wrapper. Run with `node --test test/*.js`.
// We intentionally avoid any third-party test runners.

const test = require('node:test');
const assert = require('node:assert/strict');

const platform = require('../lib/platform');

test('detect darwin/arm64 maps to darwin_arm64 tar.gz', () => {
  const p = platform.detect('darwin', 'arm64');
  assert.equal(p.os, 'darwin');
  assert.equal(p.arch, 'arm64');
  assert.equal(p.ext, '.tar.gz');
  assert.equal(p.binName, 'yalla');
  assert.equal(p.archive('1.2.3'), 'yalla_1.2.3_darwin_arm64.tar.gz');
});

test('detect linux/x64 maps to linux_amd64 tar.gz', () => {
  const p = platform.detect('linux', 'x64');
  assert.equal(p.archive('0.1.0'), 'yalla_0.1.0_linux_amd64.tar.gz');
  assert.equal(p.binName, 'yalla');
});

test('detect win32/x64 maps to windows_amd64 zip + yalla.exe', () => {
  const p = platform.detect('win32', 'x64');
  assert.equal(p.os, 'windows');
  assert.equal(p.arch, 'amd64');
  assert.equal(p.ext, '.zip');
  assert.equal(p.binName, 'yalla.exe');
  assert.equal(p.archive('2.0.0'), 'yalla_2.0.0_windows_amd64.zip');
});

test('detect throws on unsupported platform', () => {
  assert.throws(() => platform.detect('aix', 'x64'), /unsupported platform/);
});

test('detect throws on unsupported arch', () => {
  assert.throws(() => platform.detect('linux', 'mips'), /unsupported architecture/);
});

test('parseChecksum picks the matching line and lowercases hex', () => {
  const text = [
    '# header',
    '',
    'AABBCCDDEEFF00112233445566778899aabbccddeeff00112233445566778899  yalla_1.0.0_linux_amd64.tar.gz',
    '0011223344556677889900112233445566778899aabbccddeeff001122334455 *yalla_1.0.0_darwin_arm64.tar.gz',
  ].join('\n');
  assert.equal(
    platform.parseChecksum(text, 'yalla_1.0.0_linux_amd64.tar.gz'),
    'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899',
  );
  assert.equal(
    platform.parseChecksum(text, 'yalla_1.0.0_darwin_arm64.tar.gz'),
    '0011223344556677889900112233445566778899aabbccddeeff001122334455',
  );
});

test('parseChecksum throws when filename missing', () => {
  assert.throws(
    () => platform.parseChecksum('aaaa  other.tar.gz', 'missing.tar.gz'),
    /not found/,
  );
});

test('checksumName follows GoReleaser default template', () => {
  assert.equal(platform.checksumName('1.2.3'), 'yalla_1.2.3_checksums.txt');
});
