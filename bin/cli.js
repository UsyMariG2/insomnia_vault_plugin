#!/usr/bin/env node
// Shim entry. Real logic lives in dist/migrate/cli.js after `npm run build`.
require("../dist/src/cli/cli").main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(`[plus4u-oidc-v2] Unhandled error: ${err && err.message ? err.message : err}`);
    process.exit(99);
  });
