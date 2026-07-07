/*
 * MUAD'DIB — Supply-chain threat detection for npm & PyPI
 * Copyright (C) 2026 DNSZLSK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

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
