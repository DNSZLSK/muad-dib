const fs = require('fs');
const path = require('path');

const { getMaxFileSize } = require('../shared/constants.js');

const YAML_EXTENSIONS = ['.yml', '.yaml'];
const MAX_DEPTH = 10;

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

      for (const { regex, msg } of injectionPatterns) {
        if (regex.test(activeContent)) {
          fileHasInjection = true;
          threats.push({
            type: 'workflow_injection',
            severity: 'HIGH',
            message: 'Potential injection: ' + msg,
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
