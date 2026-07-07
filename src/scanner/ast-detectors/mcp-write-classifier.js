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

/**
 * mcp-write-classifier.js — pure 3-tier classifier for mcp_config_injection
 * candidates (SHADOW adjudication + the future severity flip).
 *
 * Empirical classes (web research 2026-06-11, calibrated on real campaigns):
 *   (a) template              — write with inert content: the scaffolder shape
 *       (ruler, rulesync, cursor-rules, cursor-tools all legitimately write
 *       .cursorrules/CLAUDE.md/AGENTS.md). Candidate MEDIUM after adjudication.
 *   (b) shell_exec            — content carries a shell command or an
 *       agent-hook exec (SafeDep campaign, 2026-05-13: .claude/settings.json
 *       SessionStart hook → ELF). Stays CRITICAL.
 *   (c) instruction_injection — content carries hidden instructions: zero-
 *       width/bidi Unicode (TrapDoor encoding — Socket 2026-05-25; GitHub
 *       flags the same) or agent-addressed directives ("do not tell the
 *       user…"). Stays CRITICAL.
 *
 * The classifier is PURE (no I/O, no ctx) so it is unit-testable per class and
 * is exactly what gets promoted when the flip lands. Until then it feeds the
 * shadow log: oldVerdict CRITICAL vs newVerdict (template→MEDIUM).
 *
 * Honest default: content that cannot be extracted statically classifies as
 * `template` with signal `dynamic_content` — we don't know, so the shadow
 * numbers must not pretend we do. (The live R5/R5b severity is unaffected
 * either way — this module emits no threats.)
 */

const { countInvisibleUnicode } = require('../../shared/unicode-invisibles.js');

// (c) — agent-addressed directives. Superset of the live R5b 3c regex
// (IMPORTANT/do-not-display/always-run) with the additions calibrated on the
// Rules-File-Backdoor / Mini-Shai-Hulud wording. Word-boundaried enough not to
// match benign docs ("important: run tests before committing" matches — by
// design, that wording addressed to an agent IS the attack shape; the
// difference is made by the write target, which the caller already gated on).
const INJECTION_DIRECTIVE_RE = /IMPORTANT[:\s]+(?:before|after|run|execute)|do\s+not\s+(?:display|show|mention|tell)|never\s+(?:mention|reveal|disclose)|hide\s+this\s+from|always\s+run/i;

// (b) — shell command in content. Same expression as the live R5b 3b gate.
const SHELL_CONTENT_RE = /(?:curl|wget)\s+[^\n]*\|\s*(?:sh|bash|zsh)\b|\beval\s*\(|\bsh\s+-c\s+|\bbash\s+-c\s+|\bnode\s+-e\s+/i;

// (b) — agent-hook exec in JSON content: a "hooks" structure carrying a
// "command" (the SafeDep .claude/settings.json SessionStart shape). Order-
// insensitive containment — the content is config the attacker controls, a
// strict JSON parse would be evadable with trailing garbage.
const HOOKS_COMMAND_RE = /"hooks"[\s\S]{0,400}"command"|"command"[\s\S]{0,400}"hooks"/;

/**
 * @param {string|null|undefined} contentStr statically-extracted write content
 *        (null/undefined = dynamic, not extractable)
 * @param {string} [checkPath] lowercased destination path (reserved for future
 *        signals; not used for class decision today)
 * @returns {{cls: 'template'|'shell_exec'|'instruction_injection', signals: string[]}}
 */
function classifyMcpWrite(contentStr, checkPath) { // eslint-disable-line no-unused-vars
  if (contentStr === null || contentStr === undefined || typeof contentStr !== 'string') {
    return { cls: 'template', signals: ['dynamic_content'] };
  }
  const signals = [];
  if (countInvisibleUnicode(contentStr) > 0) signals.push('zero_width_unicode');
  if (INJECTION_DIRECTIVE_RE.test(contentStr)) signals.push('injection_directive');
  if (signals.length > 0) return { cls: 'instruction_injection', signals };

  if (SHELL_CONTENT_RE.test(contentStr)) signals.push('shell_command');
  if (HOOKS_COMMAND_RE.test(contentStr)) signals.push('hooks_command_json');
  if (signals.length > 0) return { cls: 'shell_exec', signals };

  return { cls: 'template', signals: [] };
}

module.exports = { classifyMcpWrite, INJECTION_DIRECTIVE_RE, SHELL_CONTENT_RE, HOOKS_COMMAND_RE };
