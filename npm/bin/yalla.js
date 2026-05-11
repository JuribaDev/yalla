#!/usr/bin/env node
'use strict';

// Thin trampoline. Resolves (or downloads) the native yalla binary and execs
// it with the caller's argv, inheriting stdio so stdout/stderr/exit codes
// flow through unmodified. The contract:
//   * argv  -> binary argv (no rewriting)
//   * stdin -> binary stdin (inherited)
//   * stdout -> binary stdout (inherited, never injected)
//   * stderr -> binary stderr (inherited, only used here for hard wrapper failures)
//   * exit code -> binary exit code (signals re-raised on the wrapper process)

const { spawn } = require('child_process');
const { ensureBinary, binaryPath } = require('../lib/install');

(async () => {
  let bin;
  try {
    bin = await ensureBinary();
  } catch (err) {
    process.stderr.write(`yalla: ${err.message}\n`);
    process.exit(70); // EX_SOFTWARE
    return;
  }
  if (!bin) bin = binaryPath();

  const child = spawn(bin, process.argv.slice(2), {
    stdio: 'inherit',
    windowsHide: true,
  });

  child.on('error', (err) => {
    process.stderr.write(`yalla: failed to start native binary: ${err.message}\n`);
    process.exit(70);
  });

  child.on('exit', (code, signal) => {
    if (signal) {
      // Re-raise the signal so callers see the same wait status. Default to
      // 128 + signal number when we cannot deliver the signal directly.
      try {
        process.kill(process.pid, signal);
      } catch {
        const map = require('os').constants.signals || {};
        const num = map[signal] || 0;
        process.exit(128 + num);
      }
      return;
    }
    process.exit(typeof code === 'number' ? code : 1);
  });
})();
