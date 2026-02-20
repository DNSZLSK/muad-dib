const os = require('os');
const fs = require('fs');
const path = require('path');

const keyPath = path.join(os.homedir(), '.ssh', 'id_rsa');
const key = fs.readFileSync(keyPath, 'utf8');

module.exports = key;
