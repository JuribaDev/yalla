'use strict';

// npm postinstall: download the matching native binary so the bin script can
// exec it without any first-run latency. We deliberately swallow errors so a
// transient network blip never breaks `npm install`. The bin script will try
// again on first invocation and surface a useful message if it still fails.

const { ensureBinary } = require('./lib/install');

const skipFlags = [
  process.env.YALLA_SKIP_DOWNLOAD,
  process.env.npm_config_yalla_skip_download,
];

if (skipFlags.some((v) => v === '1' || v === 'true')) {
  process.stderr.write('yalla: YALLA_SKIP_DOWNLOAD set; skipping binary download.\n');
  process.exit(0);
}

ensureBinary().then(
  (bin) => {
    process.stderr.write(`yalla: binary ready at ${bin}\n`);
  },
  (err) => {
    process.stderr.write(
      `yalla: postinstall download failed (${err.message}); will retry on first run.\n`,
    );
    // Exit 0 so npm install keeps succeeding. The bin script re-attempts the
    // download lazily and surfaces a hard error if even that fails.
    process.exit(0);
  },
);
