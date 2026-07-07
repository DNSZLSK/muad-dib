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
