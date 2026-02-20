const fs = require('fs');
const data = fs.readFileSync('.npmrc', 'utf8');
module.exports = data;
