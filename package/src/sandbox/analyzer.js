/**
 * MUAD'DIB Sandbox Preload Log Analyzer
 *
 * Parses [PRELOAD] log lines produced by docker/preload.js and generates
 * scored findings for behavioral analysis. Seven detection rules:
 *
 *   1. sandbox_timer_delay_suspicious — timer delay > 1h (MEDIUM, +15)
 *   2. sandbox_timer_delay_critical   — timer delay > 24h (CRITICAL, +30, supersedes #1)
 *   3. sandbox_preload_sensitive_read  — sensitive file read (HIGH, +20)
 *   4. sandbox_network_after_sensitive_read — network call after sensitive read (CRITICAL, +40)
 *   5. sandbox_exec_suspicious        — dangerous command execution (HIGH, +25)
 *   6. sandbox_env_token_access       — sensitive env var access (MEDIUM, +10)
 *   7. sandbox_native_addon_load      — native .node addon loaded (MEDIUM, +15)
 */

const ONE_HOUR_MS = 3600000;
const TWENTY_FOUR_HOURS_MS = 24 * ONE_HOUR_MS;

/**
 * Parse [PRELOAD] log content and produce scored findings.
 *
 * @param {string} logContent - Raw preload log content
 * @returns {{ score: number, findings: Array<{type: string, severity: string, detail: string, evidence: string}> }}
 */
/**
 * Validate that a log line has the expected [PRELOAD] CATEGORY: format.
 * Rejects lines that don't match the expected structure to prevent
 * log injection attacks where malware injects fake preload log lines.
 */
const VALID_CATEGORIES = new Set([
  'INIT', 'TIME', 'TIMER', 'NETWORK', 'FS_READ', 'FS_WRITE',
  'EXEC', 'ENV_ACCESS', 'NATIVE_ADDON', 'WORKER'
]);

function isValidPreloadLine(line) {
  if (!line || !line.includes('[PRELOAD]')) return false;
  // Must match format: [PRELOAD] CATEGORY: ... (t+NNNms)
  const match = line.match(/^\[PRELOAD\]\s+(\w+):/);
  if (!match) return false;
  return VALID_CATEGORIES.has(match[1]);
}

function analyzePreloadLog(logContent) {
  const findings = [];
  let score = 0;

  if (!logContent || typeof logContent !== 'string') {
    return { score: 0, findings: [] };
  }

  const lines = logContent.split('\n').filter(l => isValidPreloadLine(l));

  // Categorize lines
  const timerLines = [];
  const fsReadLines = [];
  const fsWriteLines = [];
  const networkLines = [];
  const execLines = [];
  const envLines = [];
  const nativeAddonLines = [];

  for (const line of lines) {
    if (line.includes('TIMER:')) {
      timerLines.push(line);
    } else if (line.includes('FS_READ:')) {
      fsReadLines.push(line);
    } else if (line.includes('FS_WRITE:')) {
      fsWriteLines.push(line);
    } else if (line.includes('NETWORK:')) {
      networkLines.push(line);
    } else if (line.includes('EXEC:')) {
      execLines.push(line);
    } else if (line.includes('ENV_ACCESS:')) {
      envLines.push(line);
    } else if (line.includes('NATIVE_ADDON:')) {
      nativeAddonLines.push(line);
    }
  }

  // ── Rule 1/2: Timer delay detection ──
  // Parse delay values from timer lines
  const delayRe = /delay=(\d+)ms/;
  let hasCriticalTimer = false;
  let hasSuspiciousTimer = false;

  for (const line of timerLines) {
    const match = line.match(delayRe);
    if (!match) continue;
    const delay = parseInt(match[1], 10);

    if (delay > TWENTY_FOUR_HOURS_MS) {
      // Critical supersedes suspicious for this specific timer
      if (!hasCriticalTimer) {
        hasCriticalTimer = true;
        score += 30;
        findings.push({
          type: 'sandbox_timer_delay_critical',
          severity: 'CRITICAL',
          detail: `Timer delay > 24h detected: ${delay}ms (${(delay / 3600000).toFixed(1)}h) — likely time-bomb`,
          evidence: line.trim()
        });
      }
    } else if (delay > ONE_HOUR_MS) {
      if (!hasSuspiciousTimer && !hasCriticalTimer) {
        hasSuspiciousTimer = true;
        score += 15;
        findings.push({
          type: 'sandbox_timer_delay_suspicious',
          severity: 'MEDIUM',
          detail: `Timer delay > 1h detected: ${delay}ms (${(delay / 3600000).toFixed(1)}h) — possible time-bomb`,
          evidence: line.trim()
        });
      }
    }
  }

  // If we found a critical timer, remove any suspicious timer finding (supersede)
  if (hasCriticalTimer && hasSuspiciousTimer) {
    const suspIdx = findings.findIndex(f => f.type === 'sandbox_timer_delay_suspicious');
    if (suspIdx !== -1) {
      score -= 15; // Remove the suspicious score since critical supersedes
      findings.splice(suspIdx, 1);
    }
  }

  // ── Rule 3: Sensitive file read ──
  const hasSensitiveRead = fsReadLines.some(l => l.includes('SENSITIVE'));
  if (hasSensitiveRead) {
    const sensitiveFiles = fsReadLines
      .filter(l => l.includes('SENSITIVE'))
      .map(l => {
        const m = l.match(/SENSITIVE\s+(.+?)(?:\s+\(t\+|$)/);
        return m ? m[1].trim() : 'unknown';
      });

    score += 20;
    findings.push({
      type: 'sandbox_preload_sensitive_read',
      severity: 'HIGH',
      detail: `Sensitive file read detected via preload: ${sensitiveFiles.join(', ')}`,
      evidence: sensitiveFiles.join(', ')
    });
  }

  // ── Rule 4: Network after sensitive read (compound) ──
  if (hasSensitiveRead && networkLines.length > 0) {
    // Check that a network event occurs AFTER a sensitive read
    // Lines are logged sequentially via appendFileSync, so order = temporal order
    const firstSensitiveReadIdx = lines.findIndex(l => l.includes('FS_READ:') && l.includes('SENSITIVE'));
    const lastNetworkIdx = lines.length - 1 - [...lines].reverse().findIndex(l => l.includes('NETWORK:'));

    if (firstSensitiveReadIdx !== -1 && lastNetworkIdx > firstSensitiveReadIdx) {
      const networkEvidence = networkLines[0].trim();
      score += 40;
      findings.push({
        type: 'sandbox_network_after_sensitive_read',
        severity: 'CRITICAL',
        detail: 'Network activity detected after sensitive file read — possible exfiltration',
        evidence: networkEvidence
      });
    }
  }

  // ── Rule 5: Suspicious exec ──
  const dangerousExecLines = execLines.filter(l => {
    if (!l.includes('DANGEROUS')) return false;
    // Skip sandbox infrastructure commands (e.g. /usr/bin/timeout wrapping node)
    if (/\btimeout\b/.test(l)) return false;
    return true;
  });
  if (dangerousExecLines.length > 0) {
    const cmds = dangerousExecLines.map(l => {
      const m = l.match(/(?:exec|execSync|spawn|spawnSync|execFile|execFileSync):\s*(.+?)(?:\s+\(t\+|$)/);
      return m ? m[1].trim() : 'unknown';
    });

    score += 25;
    findings.push({
      type: 'sandbox_exec_suspicious',
      severity: 'HIGH',
      detail: `Dangerous command execution detected: ${cmds.join('; ')}`,
      evidence: cmds.join('; ')
    });
  }

  // ── Rule 6: Env token access ──
  if (envLines.length > 0) {
    const vars = envLines.map(l => {
      const m = l.match(/ENV_ACCESS:\s*(\S+)/);
      return m ? m[1] : 'unknown';
    });
    const unique = [...new Set(vars)];

    score += 10;
    findings.push({
      type: 'sandbox_env_token_access',
      severity: 'MEDIUM',
      detail: `Sensitive env var access detected: ${unique.join(', ')}`,
      evidence: unique.join(', ')
    });
  }

  // ── Rule 7: Native addon loading ──
  // Native addons (.node files) can bypass all JS monkey-patches via syscalls.
  // Flag their loading so analysts know time-based evasion may be undetected.
  if (nativeAddonLines.length > 0) {
    const addons = nativeAddonLines.map(l => {
      const m = l.match(/process\.dlopen:\s*(.+?)(?:\s+\(t\+|$)/);
      return m ? m[1].trim() : 'unknown';
    });

    score += 15;
    findings.push({
      type: 'sandbox_native_addon_load',
      severity: 'MEDIUM',
      detail: `Native addon loaded (${addons.length}): time-based evasion via syscalls possible`,
      evidence: addons.join(', ')
    });
  }

  return {
    score: Math.min(100, score),
    findings
  };
}

module.exports = { analyzePreloadLog, isValidPreloadLine };
