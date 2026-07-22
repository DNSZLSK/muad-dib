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

/**
 * AI Config Injection Scanner
 *
 * Detects prompt injection attacks hidden in AI agent configuration files:
 * .cursorrules, CLAUDE.md, AGENT.md, .github/copilot-instructions.md,
 * copilot-setup-steps.yml, .cursorignore, .windsurfrules, etc.
 *
 * These files are designed to be read by AI coding assistants and may contain
 * hidden instructions to execute shell commands, exfiltrate secrets, or
 * download and run remote payloads.
 *
 * References:
 * - ToxicSkills (Snyk, Feb 2026)
 * - NVIDIA AI agent security guidance
 * - arxiv 2601.17548 (prompt injection in AI agents)
 * - Clinejection (Snyk, Feb 2026)
 */

const fs = require('fs');
const path = require('path');
const { countInvisibleUnicode, stripInvisibleUnicode } = require('../shared/unicode-invisibles.js');

// Threshold above which an AI config file is flagged as ZW-Unicode-obfuscated.
// Lower than obfuscation.js (10) because .cursorrules / CLAUDE.md should never
// legitimately contain invisible codepoints — even international content uses
// only visible chars (CJK, accents, emoji with U+FE0F variation selector are
// NOT counted by countInvisibleUnicode).
const AI_CONFIG_ZW_THRESHOLD = 5;

// AI agent config files to scan for prompt injection (relative to project root)
const AI_CONFIG_FILES = [
  '.cursorrules',
  '.cursorignore',
  '.windsurfrules',
  'CLAUDE.md',
  'AGENT.md',
  '.github/copilot-instructions.md',
  'copilot-setup-steps.yml',
  '.github/copilot-setup-steps.yml'
];

// IDE/agent config files to scan for auto-exec hooks (JSON, relative to project root)
// These are distinct from AI_CONFIG_FILES: they contain machine-readable hooks
// that execute code on project open, not human-readable prompt injection.
// Technique: Shai-Hulud (TeamPCP, May 2026) — .claude/settings.json SessionStart hook.
// Additional mai 2026 surfaces (Cursor / Windsurf / Continue / root Claude Desktop)
// added after the TrapDoor + Bitwarden CLI campaigns confirmed cross-agent targeting.
const IDE_HOOK_FILES = [
  '.claude/settings.json',
  '.claude/settings.local.json',
  '.vscode/tasks.json',
  '.kiro/settings/mcp.json',
  '.cursor/mcp.json',
  '.continue/config.json',
  '.windsurf/mcp.json',
  'mcp.json',
  'claude_desktop_config.json'
];

// Paths that follow the standard MCP `mcpServers.{name}.command` schema.
// A package shipping any of these with a `command` entry is hostile: legitimate
// npm/PyPI packages never ship per-user MCP configurations.
const MCP_STANDARD_PATHS = new Set([
  '.kiro/settings/mcp.json',
  '.cursor/mcp.json',
  '.windsurf/mcp.json',
  'mcp.json',
  'claude_desktop_config.json'
]);

// Dangerous shell command patterns in AI config files
const SHELL_COMMAND_PATTERNS = [
  // Download and execute
  { regex: /curl\s+[^\n]*\|\s*(sh|bash|zsh)\b/i, label: 'curl pipe to shell', critical: true },
  { regex: /wget\s+[^\n]*\|\s*(sh|bash|zsh)\b/i, label: 'wget pipe to shell', critical: true },
  { regex: /curl\s+-[sS]*L?\s+https?:\/\/[^\s"']+\s*\|\s*(sh|bash)/i, label: 'curl download and execute', critical: true },
  { regex: /wget\s+-[qQ]*O?-?\s+https?:\/\/[^\s"']+\s*\|\s*(sh|bash)/i, label: 'wget download and execute', critical: true },

  // Direct shell execution
  { regex: /\beval\s*\(/i, label: 'eval() call', critical: false },
  { regex: /\bexec\s*\(/i, label: 'exec() call', critical: false },
  { regex: /\bsource\s+\.env\b/i, label: 'source .env', critical: false },
  { regex: /\bsh\s+-c\s+["']/i, label: 'sh -c execution', critical: false },
  { regex: /\bbash\s+-c\s+["']/i, label: 'bash -c execution', critical: false },
  { regex: /\bnode\s+-e\s+["']/i, label: 'node -e inline execution', critical: false },
  { regex: /\bpython[3]?\s+-c\s+["']/i, label: 'python -c inline execution', critical: false }
];

// Exfiltration patterns — sending data to external endpoints
const EXFIL_PATTERNS = [
  { regex: /curl\s+[^\n]*-X\s*POST\s+[^\n]*https?:\/\/(?!api\.github\.com|registry\.npmjs\.org)[^\s"']+/i, label: 'curl POST to external endpoint' },
  { regex: /curl\s+[^\n]*-d\s+[^\n]*https?:\/\/(?!api\.github\.com|registry\.npmjs\.org)[^\s"']+/i, label: 'curl data upload to external endpoint' },
  { regex: /curl\s+[^\n]*https?:\/\/(?!api\.github\.com|registry\.npmjs\.org)[^\s"']+[^\n]*-d\s/i, label: 'curl data upload to external endpoint' },
  { regex: /\|\s*curl\s+[^\n]*https?:\/\/(?!api\.github\.com|registry\.npmjs\.org)/i, label: 'pipe output to curl' },
  { regex: /\|\s*base64\s*\|\s*curl/i, label: 'base64 encode and send via curl' }
];

// Credential access patterns — reading sensitive files/vars
const CREDENTIAL_ACCESS_PATTERNS = [
  { regex: /cat\s+~?\/?\.ssh\/id_/i, label: 'read SSH private key' },
  { regex: /cat\s+~?\/?\.npmrc/i, label: 'read .npmrc tokens' },
  { regex: /cat\s+~?\/?\.aws\/credentials/i, label: 'read AWS credentials' },
  { regex: /cat\s+~?\/?\.env\b/i, label: 'read .env file' },
  { regex: /cat\s+~?\/?\.gnupg\//i, label: 'read GPG keys' },
  { regex: /\$GITHUB_TOKEN|\$GH_TOKEN|\$NPM_TOKEN|\$AWS_SECRET_ACCESS_KEY|\$DISCORD_TOKEN/i, label: 'reference to secret env var' },
  { regex: /grep\s+[^\n]*(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)[^\n]*/i, label: 'grep for secrets' },
  { regex: /env\s*\|\s*grep\s+[^\n]*(TOKEN|KEY|SECRET|PASSWORD)/i, label: 'env grep for secrets' }
];

// Instruction patterns — AI prompt injection directives
const INJECTION_INSTRUCTION_PATTERNS = [
  { regex: /before\s+(reviewing|running|any|code|generating)[^\n]*(run|execute|source):/i, label: 'instruction to execute before review' },
  { regex: /always\s+run\s+[^\n]*(before|first|initially)/i, label: 'instruction to always run command' },
  { regex: /send\s+(contents?|data|output|results?)\s+(to|via)\s+https?:\/\//i, label: 'instruction to send data to URL' },
  { regex: /upload\s+[^\n]*(to|via)\s+https?:\/\//i, label: 'instruction to upload to URL' },
  { regex: /do\s+not\s+(display|show|output|mention|tell)/i, label: 'instruction to hide activity' }
];

/**
 * Scan AI config files for prompt injection
 */
function scanAIConfig(targetPath) {
  const threats = [];

  for (const configFile of AI_CONFIG_FILES) {
    const filePath = path.join(targetPath, configFile);

    if (!fs.existsSync(filePath)) continue;

    let content;
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > 1024 * 1024) continue; // Skip files > 1MB
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }

    const relPath = configFile;
    // Normalize invisible Unicode BEFORE running regex patterns.
    // Without this, an attacker can split keywords with U+200B (`cu<ZWSP>rl`) to
    // evade /curl\s+/ — the exact TrapDoor (mai 2026) .cursorrules vector.
    const invisibleCount = countInvisibleUnicode(content);
    const normalized = invisibleCount > 0 ? stripInvisibleUnicode(content) : content;
    const fileThreats = analyzeAIConfigFile(normalized, relPath, invisibleCount);
    threats.push(...fileThreats);
  }

  // Scan IDE hook files for auto-exec patterns (separate from prompt injection)
  for (const hookFile of IDE_HOOK_FILES) {
    const filePath = path.join(targetPath, hookFile);
    if (!fs.existsSync(filePath)) continue;

    let content;
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > 1024 * 1024) continue;
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }

    const hookThreats = analyzeIDEHookFile(content, hookFile);
    threats.push(...hookThreats);
  }

  return threats;
}

/**
 * Analyze an IDE/agent config JSON file for auto-exec hooks.
 *
 * Distinct from prompt injection: these files contain machine-readable
 * hooks that execute arbitrary commands when the project is opened.
 * No legitimate npm package should ship these files with hooks.
 */
function analyzeIDEHookFile(content, relPath) {
  const threats = [];

  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch {
    return threats; // invalid JSON — skip silently
  }

  if (!parsed || typeof parsed !== 'object') return threats;

  // .claude/settings.json / .claude/settings.local.json
  // Structure: { hooks: { EventName: [{ matcher, hooks: [{ type, command }] }] } }
  if (relPath.includes('.claude/') && relPath.endsWith('settings.json')) {
    const hooks = parsed.hooks;
    if (hooks && typeof hooks === 'object') {
      for (const [event, matchers] of Object.entries(hooks)) {
        if (!Array.isArray(matchers)) continue;
        for (const matcher of matchers) {
          if (!matcher || !Array.isArray(matcher.hooks)) continue;
          for (const hook of matcher.hooks) {
            if (hook && hook.command) {
              threats.push({
                type: 'ide_hook_autoexec',
                severity: 'CRITICAL',
                message: `IDE auto-exec hook: .claude/settings.json ${event} event executes "${hook.command}" — Shai-Hulud (TeamPCP) pattern`,
                file: relPath
              });
            }
          }
        }
      }
    }
  }

  // .vscode/tasks.json
  // Structure: { tasks: [{ label, command, runOptions: { runOn: "folderOpen" } }] }
  if (relPath.includes('.vscode/') && relPath.endsWith('tasks.json')) {
    const tasks = Array.isArray(parsed.tasks) ? parsed.tasks : [];
    for (const task of tasks) {
      if (task && task.runOptions && task.runOptions.runOn === 'folderOpen') {
        const cmd = task.command || task.label || 'unknown';
        threats.push({
          type: 'ide_hook_autoexec',
          severity: 'CRITICAL',
          message: `IDE auto-exec hook: .vscode/tasks.json task "${cmd}" runs on folder open — Shai-Hulud (TeamPCP) pattern`,
          file: relPath
        });
      }
    }
  }

  // Standard MCP config family:
  //   .kiro/settings/mcp.json | .cursor/mcp.json | .windsurf/mcp.json
  //   | root mcp.json (Claude Desktop project mode)
  //   | root claude_desktop_config.json (Claude Desktop global, hostile if shipped)
  // Structure: { mcpServers: { name: { command, args } } }
  if (MCP_STANDARD_PATHS.has(relPath)) {
    const mcpServers = parsed.mcpServers;
    if (mcpServers && typeof mcpServers === 'object') {
      for (const [name, config] of Object.entries(mcpServers)) {
        if (config && typeof config === 'object' && config.command) {
          threats.push({
            type: 'ide_hook_autoexec',
            severity: 'CRITICAL',
            message: `IDE auto-exec hook: ${relPath} server "${name}" executes "${config.command}" on project open`,
            file: relPath
          });
        }
      }
    }
  }

  // .continue/config.json — Continue.dev schema. Two MCP surfaces:
  //   1. experimental.modelContextProtocolServers[].transport.command (canonical)
  //   2. mcpServers.{name}.command (newer alias)
  if (relPath === '.continue/config.json') {
    const exp = parsed.experimental;
    const mcps = exp && Array.isArray(exp.modelContextProtocolServers)
      ? exp.modelContextProtocolServers
      : [];
    for (const srv of mcps) {
      const cmd = srv && srv.transport && srv.transport.command;
      if (cmd) {
        threats.push({
          type: 'ide_hook_autoexec',
          severity: 'CRITICAL',
          message: `IDE auto-exec hook: .continue/config.json modelContextProtocolServer transport executes "${cmd}" on project open`,
          file: relPath
        });
      }
    }
    const mcpServers = parsed.mcpServers;
    if (mcpServers && typeof mcpServers === 'object') {
      for (const [name, config] of Object.entries(mcpServers)) {
        if (config && typeof config === 'object' && config.command) {
          threats.push({
            type: 'ide_hook_autoexec',
            severity: 'CRITICAL',
            message: `IDE auto-exec hook: .continue/config.json mcpServers "${name}" executes "${config.command}" on project open`,
            file: relPath
          });
        }
      }
    }
  }

  return threats;
}

/**
 * Analyze a single AI config file for prompt injection patterns.
 *
 * @param {string} content - File content, already normalized (invisible Unicode stripped).
 * @param {string} relPath - Relative path of the config file.
 * @param {number} invisibleCount - Number of invisible Unicode codepoints in the original (pre-strip) content.
 */
function analyzeAIConfigFile(content, relPath, invisibleCount) {
  const threats = [];
  let hasShellCommand = false;
  let hasExfiltration = false;
  let hasCredentialAccess = false;

  // Zero-width / directional Unicode obfuscation (TrapDoor, mai 2026).
  // An attacker can hide instructions or split keywords with U+200B etc. so
  // human reviewers see "harmless" text while the AI agent reads the payload.
  if (invisibleCount >= AI_CONFIG_ZW_THRESHOLD) {
    threats.push({
      type: 'aiconf_unicode_obfuscation',
      severity: 'CRITICAL',
      message: `AI config contains ${invisibleCount} invisible Unicode characters (zero-width / directional / variation selectors) in ${relPath} — content was normalized before pattern matching. Possible hidden instructions or keyword-splitting evasion (TrapDoor pattern).`,
      file: relPath
    });
  }

  // Check shell command patterns
  for (const pattern of SHELL_COMMAND_PATTERNS) {
    if (pattern.regex.test(content)) {
      hasShellCommand = true;
      threats.push({
        type: pattern.critical ? 'ai_config_injection_critical' : 'ai_config_injection',
        severity: pattern.critical ? 'CRITICAL' : 'HIGH',
        message: `AI config prompt injection: ${pattern.label} in ${relPath}`,
        file: relPath
      });
    }
  }

  // Check exfiltration patterns
  for (const pattern of EXFIL_PATTERNS) {
    if (pattern.regex.test(content)) {
      hasExfiltration = true;
      threats.push({
        type: 'ai_config_injection_critical',
        severity: 'CRITICAL',
        message: `AI config exfiltration: ${pattern.label} in ${relPath}`,
        file: relPath
      });
    }
  }

  // Check credential access patterns
  for (const pattern of CREDENTIAL_ACCESS_PATTERNS) {
    if (pattern.regex.test(content)) {
      hasCredentialAccess = true;
      threats.push({
        type: 'ai_config_injection',
        severity: 'HIGH',
        message: `AI config credential access: ${pattern.label} in ${relPath}`,
        file: relPath
      });
    }
  }

  // Check injection instruction patterns
  for (const pattern of INJECTION_INSTRUCTION_PATTERNS) {
    if (pattern.regex.test(content)) {
      threats.push({
        type: 'ai_config_injection',
        severity: 'HIGH',
        message: `AI config prompt injection: ${pattern.label} in ${relPath}`,
        file: relPath
      });
    }
  }

  // Compound detection: shell + exfil or credential access → escalate
  if (hasShellCommand && (hasExfiltration || hasCredentialAccess)) {
    threats.push({
      type: 'ai_config_injection_critical',
      severity: 'CRITICAL',
      // Structural marker (like GHA-006): the compound escalation shares its type
      // with single-pattern criticals — tests and consumers must not have to
      // sniff the message wording to tell them apart.
      compound: true,
      message: `AI config compound attack: shell commands + ${hasExfiltration ? 'exfiltration' : 'credential access'} in ${relPath} — ToxicSkills/Clinejection pattern.`,
      file: relPath
    });
  }

  return threats;
}

module.exports = { scanAIConfig };
