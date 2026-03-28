'use strict';

const { handleVariableDeclarator } = require('./handle-variable-declarator.js');
const { handleCallExpression } = require('./handle-call-expression.js');
const { handleImportExpression } = require('./handle-import-expression.js');
const { handleNewExpression } = require('./handle-new-expression.js');
const { handleLiteral } = require('./handle-literal.js');
const { handleAssignmentExpression } = require('./handle-assignment-expression.js');
const { handleMemberExpression } = require('./handle-member-expression.js');
const { handleWithStatement } = require('./handle-with-statement.js');
const { handlePostWalk } = require('./handle-post-walk.js');

module.exports = {
  handleVariableDeclarator,
  handleCallExpression,
  handleImportExpression,
  handleNewExpression,
  handleLiteral,
  handleAssignmentExpression,
  handleMemberExpression,
  handleWithStatement,
  handlePostWalk
};
