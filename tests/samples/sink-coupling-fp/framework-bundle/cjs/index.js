"use strict";
// ui-kit-bundle — development build (vendored). Ships credential-redaction
// helpers (token-SHAPED regexes + placeholder example keys) plus an unrelated
// version-check call. credential_regex_harvest fires here (credential-keyword
// regex + network-call-in-file), BUT the matched strings never flow into the
// request and the destination is first-party (registry.npmjs.org) — there is
// no exfil sink. This is the react-markup / @sveltejs/kit class of FP.
const https = require("https");

const REDACTION_PATTERNS = [
  /AKIA[0-9A-Z]{16}/,
  /ghp_[A-Za-z0-9]{36}/,
  /(?:bearer|token)\s+[A-Za-z0-9._\-]{20,}/i,
  /-----BEGIN (?:RSA )?PRIVATE KEY-----/
];

const PLACEHOLDERS = {
  awsAccessKeyId: "AKIAIOSFODNN7EXAMPLE",
  githubToken: "ghp_000000000000000000000000000000000000",
  authHeader: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.x"
};

function redact(input) {
  return REDACTION_PATTERNS.reduce((acc, re) => acc.replace(re, "[REDACTED]"), String(input));
}

// Unrelated, benign version check to the package's own registry entry.
// The credential values above never reach this request.
function checkLatest(cb) {
  https.get("https://registry.npmjs.org/ui-kit-bundle/latest", (res) => {
    let body = "";
    res.on("data", (d) => { body += d; });
    res.on("end", () => { try { cb(null, JSON.parse(body).version); } catch (e) { cb(e); } });
  }).on("error", cb);
}

module.exports = { redact, checkLatest, _placeholders: PLACEHOLDERS };
