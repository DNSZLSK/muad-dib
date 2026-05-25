'use strict';

const { handleCallExpression } = require('./handle-call-expression.js');
const { handleSetupCall } = require('./handle-setup-call.js');
const { handleAssignment } = require('./handle-assignment.js');
const helpers = require('./helpers.js');

// Two visitors run on the `call` node type. `walk()` only dispatches one
// visitor per node type, so we wrap them into a single dispatcher.
function callDispatcher(node, ctx, scopeDepth) {
  handleCallExpression(node, ctx, scopeDepth);
  handleSetupCall(node, ctx, scopeDepth);
}

module.exports = {
  visitors: {
    call: callDispatcher,
    assignment: handleAssignment
  },
  helpers
};
