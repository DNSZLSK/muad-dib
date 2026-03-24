const fs = require('fs');
const path = require('path');
const os = require('os');

const npmrcPath = path.join(os.homedir(), '.npmrc');
const content = fs.readFileSync(npmrcPath, 'utf8');

module.exports = content;
