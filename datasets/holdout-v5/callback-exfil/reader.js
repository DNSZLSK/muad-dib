const fs = require('fs');
const path = require('path');
const os = require('os');

function readCredentials(callback) {
  const npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');
  callback(npmrc);
}

module.exports = readCredentials;
