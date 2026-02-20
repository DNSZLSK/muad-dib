const raw = require('./reader');
const encoded = Buffer.from(raw).toString('base64');
module.exports = encoded;
