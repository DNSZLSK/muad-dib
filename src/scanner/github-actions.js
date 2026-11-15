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

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const { getMaxFileSize } = require('../shared/constants.js');

const YAML_EXTENSIONS = ['.yml', '.yaml'];
const MAX_DEPTH = 10;

// The code a workflow or composite action executes with expressions expanded in place: each
// step's `run:` script and the `script:` input of actions/github-script. An expression there
// is substituted into the code before it runs (script injection). Passed through `env:` (the
// mitigation GitHub documents), it is data. Returns { scripts, actionInputs }, or null when
// the file is not a parsable workflow / action: the caller then keeps the whole-file match.
function parseWorkflowSteps(content) {
  let doc;
  try {
    doc = yaml.load(content, { schema: yaml.JSON_SCHEMA });
  } catch {
    return null;
  }
  if (!doc || typeof doc !== 'object') return null;
  const stepLists = [];
  if (doc.jobs && typeof doc.jobs === 'object') {
    for (const job of Object.values(doc.jobs)) if (job && Array.isArray(job.steps)) stepLists.push(job.steps);
  }
  if (doc.runs && Array.isArray(doc.runs.steps)) stepLists.push(doc.runs.steps);
  if (stepLists.length === 0) return null;
  const scripts = [];
  // Inputs of actions other than the first-party actions/* and github/* (local, third-party,
  // docker): whether such an action interpolates an input into its own shell (a composite
  // action writing ${{ inputs.x }} in run:, cf. CVE-2023-49291) cannot be seen from here.
  const actionInputs = [];
  for (const steps of stepLists) {
    for (const step of steps) {
      if (!step || typeof step !== 'object') continue;
      if (typeof step.run === 'string') scripts.push(step.run);
      if (typeof step.uses !== 'string' || !step.with || typeof step.with !== 'object') continue;
      if (/^actions\/github-script@/i.test(step.uses)) {
        if (typeof step.with.script === 'string') scripts.push(step.with.script);
        continue;
      }
      const org = step.uses.split('/')[0].toLowerCase();
      if (org === 'actions' || org === 'github') continue;
      for (const [input, value] of Object.entries(step.with)) {
        if (typeof value === 'string') actionInputs.push({ uses: step.uses, input, value });
      }
    }
  }
  return { scripts, actionInputs };
}

// What a LOCAL action (`uses: ./path`, resolved from the repository root like GitHub does)
// does with one of its inputs, read from its own action.yml / action.yaml:
//   'shell'   a composite step's run: (or github-script script:) expands ${{ inputs.<name> }}
//   'forward' it only passes the input on (a nested action's with:, docker args): unknown
//   'data'    a node action (inputs arrive as INPUT_* variables) or no expansion at all
//   'unknown' action file missing, unreadable, unparsable, or outside the scanned tree
function localActionUse(targetPath, uses, input) {
  const root = path.resolve(targetPath);
  const dir = path.resolve(root, uses.replace(/@.*$/, ''));
  const rel = path.relative(root, dir);
  if (rel.startsWith('..') || path.isAbsolute(rel)) return 'unknown';
  let content = null;
  for (const name of ['action.yml', 'action.yaml']) {
    const f = path.join(dir, name);
    try {
      const st = fs.lstatSync(f);
      if (!st.isFile() || st.size > getMaxFileSize()) continue;
      content = fs.readFileSync(f, 'utf8');
      break;
    } catch { /* try the next name */ }
  }
  if (content === null) return 'unknown';
  let doc;
  try { doc = yaml.load(content, { schema: yaml.JSON_SCHEMA }); } catch { return 'unknown'; }
  if (!doc || typeof doc !== 'object' || !doc.runs || typeof doc.runs !== 'object') return 'unknown';
  const esc = input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const ref = new RegExp(`\\$\\{\\{[^}]*\\binputs(?:\\.${esc}\\b|\\[\\s*['"]${esc}['"]\\s*\\])`);
  const using = String(doc.runs.using || '').toLowerCase();
  if (using === 'composite') {
    const steps = Array.isArray(doc.runs.steps) ? doc.runs.steps : [];
    let forwarded = false;
    for (const step of steps) {
      if (!step || typeof step !== 'object') continue;
      if (typeof step.run === 'string' && ref.test(step.run)) return 'shell';
      if (step.with && typeof step.with === 'object') {
        if (typeof step.uses === 'string' && /^actions\/github-script@/i.test(step.uses) &&
            typeof step.with.script === 'string' && ref.test(step.with.script)) return 'shell';
        if (Object.values(step.with).some(v => typeof v === 'string' && ref.test(v))) forwarded = true;
      }
    }
    return forwarded ? 'forward' : 'data';
  }
  if (using === 'docker') {
    const args = Array.isArray(doc.runs.args) ? doc.runs.args : [];
    return args.some(a => typeof a === 'string' && ref.test(a)) ? 'forward' : 'data';
  }
  if (using.startsWith('node')) return 'data';
  return 'unknown';
}

function scanGitHubActions(targetPath) {
  const threats = [];

  // Scan both workflows and custom actions directories
  const dirsToScan = [
    path.join(targetPath, '.github', 'workflows'),
    path.join(targetPath, '.github', 'actions')
  ];

  for (const dirPath of dirsToScan) {
    if (!fs.existsSync(dirPath)) continue;
    scanDirRecursive(dirPath, targetPath, threats);
  }

  return threats;
}

function scanDirRecursive(dirPath, targetPath, threats, depth = 0) {
  if (depth > MAX_DEPTH) return;
  let files;
  try { files = fs.readdirSync(dirPath); } catch { return; }
  const relDir = path.relative(targetPath, dirPath).replace(/\\/g, '/');

  for (const file of files) {
    const filePath = path.join(dirPath, file);

    try {
      const stat = fs.lstatSync(filePath);
      if (stat.isSymbolicLink()) continue;
      if (stat.isDirectory()) {
        scanDirRecursive(filePath, targetPath, threats, depth + 1);
        continue;
      }
      if (!stat.isFile()) continue;
      if (stat.size > getMaxFileSize()) continue;
    } catch {
      continue;
    }

    // Only process YAML files
    if (!YAML_EXTENSIONS.some(ext => file.endsWith(ext))) continue;

      let content;
      try {
        content = fs.readFileSync(filePath, 'utf8');
      } catch {
        continue;
      }

      const relFile = `${relDir}/${file}`;

      // GHA-001: Line-by-line YAML-aware parsing (skip comments)
      const yamlLines = content.split(/\r?\n/);
      const activeLines = yamlLines.filter(l => !l.trim().startsWith('#'));
      const activeContent = activeLines.join('\n');

      // Per-file risk flags, consumed by the GHA-006 compound below.
      let fileHasInjection = false;
      let fileHasPwn = false;

      // Détection du backdoor Shai-Hulud discussion.yaml
      if (file === 'discussion.yaml' || file === 'discussion.yml') {
        if (activeContent.includes('github.event.discussion.body')) {
          threats.push({
            type: 'shai_hulud_backdoor',
            severity: 'CRITICAL',
            message: 'Backdoor Shai-Hulud détecté: workflow discussion.yaml avec injection via discussion body',
            file: relFile
          });
        }
      }

      // GHA-002: Detect attacker-controlled context injection on ALL runners (not just self-hosted)
      const injectionPatterns = [
        { regex: /\$\{\{\s*github\.event\.(comment\.body|issue\.body|issue\.title|pull_request\.body|pull_request\.title|discussion\.body|discussion\.title|pages\[\]\.html_url)/, msg: 'Attacker-controlled GitHub event context used in workflow' },
        { regex: /\$\{\{\s*github\.head_ref/, msg: 'github.head_ref is attacker-controlled in pull_request workflows' }
      ];

      // Matched only in executed code (run / github-script) when the file parses; a value
      // passed through env: is the documented mitigation, not an injection. Unparsable file:
      // whole-file match, as before.
      const parsed = parseWorkflowSteps(content);
      const injectionScope = parsed === null ? [activeContent] : parsed.scripts;
      for (const { regex, msg } of injectionPatterns) {
        if (injectionScope.some(s => regex.test(s))) {
          fileHasInjection = true;
          threats.push({
            type: 'workflow_injection',
            severity: 'HIGH',
            message: 'Potential injection: ' + msg,
            file: relFile
          });
        }
      }

      // GHA-007: the same attacker-controlled context handed as an input to an action other
      // than actions/* and github/*. Injectable only if that action expands the input into its
      // own shell. A local action's action.yml is in the scanned tree and is read: expansion
      // in a run: is a real injection (workflow_injection), a node action or no expansion is
      // data (nothing reported). A third-party action, or a local one that only forwards the
      // input or cannot be read, cannot be decided: MEDIUM, a separate type, and NOT an
      // injection for the GHA-006 compound (which would make it CRITICAL on a maybe).
      if (parsed !== null) {
        const seen = new Set();
        for (const { uses, input, value } of parsed.actionInputs) {
          if (seen.has(uses + '|' + input) || !injectionPatterns.some(p => p.regex.test(value))) continue;
          seen.add(uses + '|' + input);
          if (uses.startsWith('./')) {
            const use = localActionUse(targetPath, uses, input);
            if (use === 'data') continue;
            if (use === 'shell') {
              fileHasInjection = true;
              threats.push({
                type: 'workflow_injection',
                severity: 'HIGH',
                message: `Potential injection: attacker-controlled GitHub event context passed as input "${input}" to local action ${uses}, which expands it in a run: step`,
                file: relFile
              });
              continue;
            }
          }
          threats.push({
            type: 'workflow_context_to_action_input',
            severity: 'MEDIUM',
            message: `Attacker-controlled GitHub event context passed as input "${input}" to ${uses}: an injection if the action expands the input into its own shell (cf. CVE-2023-49291)`,
            file: relFile
          });
        }
      }

      // GHA-003: Compound — pull_request_target + checkout of PR head (pwn request)
      const hasPRTarget = /pull_request_target/m.test(activeContent);
      const hasCheckoutPRHead = /actions\/checkout[\s\S]*?ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(ref|sha)\s*\}\}/m.test(activeContent);
      if (hasPRTarget && hasCheckoutPRHead) {
        fileHasPwn = true;
        threats.push({
          type: 'workflow_pwn_request',
          severity: 'CRITICAL',
          message: 'Pwn request: pull_request_target with checkout of PR head ref/sha allows arbitrary code execution',
          file: relFile
        });
      }

      // GHA-004: Secrets dump via toJSON(secrets) — exfiltrates ALL repository secrets
      // Technique: Shai-Hulud (TeamPCP, May 2026) — workflow dumps toJSON(secrets) to a
      // file and uploads it as an artifact. No legitimate workflow uses toJSON(secrets).
      if (/toJSON\s*\(\s*secrets\s*\)/.test(activeContent)) {
        threats.push({
          type: 'workflow_secrets_dump',
          severity: 'CRITICAL',
          message: 'GitHub Actions secrets dump: toJSON(secrets) exfiltrates all repository secrets',
          file: relFile
        });
      }

      // GHA-005: Unpinned THIRD-PARTY action — pinned to a mutable tag/branch ref
      // instead of an immutable commit SHA. Root cause of the tj-actions/changed-files
      // (CVE-2025-30066) and reviewdog (CVE-2025-30154) compromises: a retagged release
      // silently ships malicious code to every consumer. LOW/informational on its own —
      // pinning to a major tag is ubiquitous and usually benign — and restricted to
      // third-party orgs (official actions/* and github/* are conventionally trusted) to
      // avoid noise on the near-universal `actions/checkout@v4`. The real signal is the
      // GHA-006 compound below.
      let fileHasUnpinnedThirdParty = false;
      const usesRe = /^\s*-?\s*uses:\s*['"]?([^'"\s#]+)/gm;
      let um;
      while ((um = usesRe.exec(activeContent)) !== null) {
        const ref = um[1];
        // Local actions (./, ../) and docker refs carry no upstream tag to retag.
        if (ref.startsWith('./') || ref.startsWith('../') || ref.startsWith('.\\') || ref.startsWith('docker://')) continue;
        const at = ref.lastIndexOf('@');
        if (at === -1) continue;
        const repo = ref.slice(0, at);
        const pin = ref.slice(at + 1);
        if (/^[0-9a-f]{40}$/i.test(pin)) continue; // immutable SHA — correctly pinned
        const org = repo.split('/')[0].toLowerCase();
        if (org === 'actions' || org === 'github') continue; // first-party trusted orgs
        fileHasUnpinnedThirdParty = true;
        threats.push({
          type: 'unpinned_action',
          severity: 'LOW',
          confidence: 'low',
          message: `Third-party GitHub Action "${ref}" is pinned to a mutable ref ("${pin}") instead of a commit SHA — a retagged release (cf. tj-actions CVE-2025-30066) would execute attacker-controlled code.`,
          file: relFile
        });
      }

      // GHA-006 compound: an unpinned third-party action in a workflow that is ALSO
      // attacker-controllable (context injection or pwn-request). This is the
      // tj-actions / Ultralytics shape — the mutable ref is the delivery vector and the
      // risky trigger is the reach. FP≈0 by construction: requires both independent halves.
      if (fileHasUnpinnedThirdParty && (fileHasInjection || fileHasPwn)) {
        threats.push({
          type: 'unpinned_action_in_risky_workflow',
          severity: 'CRITICAL',
          compound: true,
          message: 'Unpinned third-party action combined with an attacker-controllable workflow trigger (injection/pwn-request) — supply-chain delivery vector (tj-actions/Ultralytics pattern).',
          file: relFile
        });
      }
    }
}

module.exports = { scanGitHubActions };
