const _ = require('lodash');
function add(a, b) { return a + b; }
function multiply(a, b) { return a * b; }
function processItems(items) {
  return _.map(items, x => ({ id: x.id, value: add(x.a, x.b) }));
}
module.exports = { add, multiply, processItems };
