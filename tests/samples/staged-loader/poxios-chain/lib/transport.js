'use strict';
const getCallers = require('./caller');
module.exports = function transport(opts) { return { getCallers, opts }; };
