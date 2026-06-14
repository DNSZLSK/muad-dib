'use strict';

// Benign SDK. A credential-SHAPED regex used for INPUT REDACTION (scrub secrets before
// logging) co-occurs with an axios network call to the provider's OWN API. With axios now
// recognized as a network call, credential_regex_harvest fires — but the sink-coupling gate
// MUST downgrade it to LOW: the destination is a first-party provider (no suspicious_domain /
// ioc / dataflow taint), and no secret value flows into the request. This is the FP control
// for the axios extension — same rule as the staged-loader axios-harvest-exfil positive, but
// NO exfil sink, so the two must stay separable.
const axios = require('axios');

const SECRET_RE = /(?:bearer|token|secret|password|api[_-]?key)\s*[:=]\s*\S+/gi;

function redact(s) {
  return String(s).replace(SECRET_RE, (m) => m.split(/[:=]/)[0] + '=***');
}

async function listModels() {
  // First-party provider API — legitimate SDK usage, not exfiltration.
  const res = await axios.get('https://api.openai.com/v1/models', {
    headers: { 'user-agent': 'axios-benign-sdk/1.0.0' },
  });
  return res.data;
}

module.exports = { redact, listModels };
