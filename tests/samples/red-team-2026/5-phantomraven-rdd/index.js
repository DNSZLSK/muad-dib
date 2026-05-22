// Innocent surface: config loader.
const _ = require('lodash');
function load(opts) { return _.merge({}, opts || {}); }
module.exports = { load };
