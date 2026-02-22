const { execFileSync } = require('child_process');
const { run } = require('./index.js');
const path = require('path');
const fs = require('fs');
const os = require('os');

// Only allow safe characters in git refs (prevents command injection)
const SAFE_REF_REGEX = /^[a-zA-Z0-9._\-/~^@{}]+$/;

/**
 * Get the list of commits/tags for comparison suggestions
 */
function getRecentRefs(targetPath, limit = 10) {
  try {
    const tags = execFileSync('git', ['tag', '--sort=-creatordate'], {
      cwd: targetPath,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    }).trim().split(/\r?\n/).filter(Boolean).slice(0, 5);

    const commits = execFileSync('git', ['log', '--oneline', `-${Number(limit) || 10}`], {
      cwd: targetPath,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    }).trim().split(/\r?\n/).filter(Boolean);

    return { tags, commits };
  } catch {
    return { tags: [], commits: [] };
  }
}

/**
 * Check if we're in a git repository
 */
function isGitRepo(targetPath) {
  try {
    execFileSync('git', ['rev-parse', '--git-dir'], {
      cwd: targetPath,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Get current commit hash
 */
function getCurrentCommit(targetPath) {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: targetPath,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    }).trim();
  } catch {
    return null;
  }
}

/**
 * Resolve a ref (tag, branch, commit) to a commit hash
 */
function resolveRef(targetPath, ref) {
  if (!SAFE_REF_REGEX.test(ref)) {
    return null;
  }
  try {
    return execFileSync('git', ['rev-parse', ref], {
      cwd: targetPath,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    }).trim();
  } catch {
    return null;
  }
}

/**
 * Check if working directory has uncommitted changes
 */
function hasUncommittedChanges(targetPath) {
  try {
    const status = execFileSync('git', ['status', '--porcelain'], {
      cwd: targetPath,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    }).trim();
    return status.length > 0;
  } catch {
    return false;
  }
}

/**
 * Create a temporary copy of the repo at a specific commit
 */
function createTempCopyAtCommit(targetPath, commitHash) {
  // Sanitize commitHash (should be a hex hash from resolveRef)
  if (!SAFE_REF_REGEX.test(commitHash)) {
    throw new Error('Invalid commit hash');
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-diff-'));

  try {
    // Clone the repo to temp directory (use execFileSync to prevent injection)
    execFileSync('git', ['clone', '--quiet', '--', targetPath, tempDir], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // Checkout the specific commit
    execFileSync('git', ['checkout', '--quiet', commitHash], {
      cwd: tempDir,
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // Install dependencies if package.json exists
    // --ignore-scripts prevents execution of malicious preinstall/postinstall
    const packageJsonPath = path.join(tempDir, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      try {
        execFileSync('npm', ['install', '--quiet', '--no-audit', '--no-fund', '--ignore-scripts'], {
          cwd: tempDir,
          stdio: ['pipe', 'pipe', 'pipe'],
          timeout: 60000
        });
      } catch {
        // Ignore npm install errors
      }
    }

    return tempDir;
  } catch (err) {
    // Clean up on error
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
    throw err;
  }
}

/**
 * Clean up temporary directory
 */
function cleanupTempDir(tempDir) {
  try {
    fs.rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore cleanup errors
  }
}

/**
 * Generate a unique threat ID for comparison
 */
function getThreatId(threat) {
  // Create a unique ID based on type, file, and message content
  const file = threat.file || '';
  const type = threat.type || '';
  const msgKey = (threat.message || '').replace(/line \d+/gi, '').trim();
  return `${type}:${file}:${msgKey}`;
}

/**
 * Compare threats between two scans
 * Returns: { added: [], removed: [], unchanged: [] }
 */
function compareThreats(oldThreats, newThreats) {
  const oldIds = new Map();
  const newIds = new Map();

  oldThreats.forEach(t => oldIds.set(getThreatId(t), t));
  newThreats.forEach(t => newIds.set(getThreatId(t), t));

  const added = [];
  const removed = [];
  const unchanged = [];

  // Find added threats (in new but not in old)
  for (const [id, threat] of newIds) {
    if (!oldIds.has(id)) {
      added.push(threat);
    } else {
      unchanged.push(threat);
    }
  }

  // Find removed threats (in old but not in new)
  for (const [id, threat] of oldIds) {
    if (!newIds.has(id)) {
      removed.push(threat);
    }
  }

  return { added, removed, unchanged };
}

/**
 * Run scan and capture results (without console output)
 */
async function runSilentScan(targetPath, options = {}) {
  const result = await run(targetPath, { ...options, _capture: true });
  if (result && typeof result === 'object' && result.threats) {
    return result;
  }
  return { threats: [], summary: { total: 0 } };
}

/**
 * Main diff function
 * @param {string} targetPath - Path to the project
 * @param {string} baseRef - Base reference (commit, tag, branch) to compare from
 * @param {object} options - Options (json, explain, etc.)
 */
async function diff(targetPath, baseRef, options = {}) {
  const resolvedPath = path.resolve(targetPath);

  // Verify git repo
  if (!isGitRepo(resolvedPath)) {
    console.error('[ERROR] Not a git repository. The diff command requires git.');
    return 1;
  }

  // Resolve base reference
  const baseCommit = resolveRef(resolvedPath, baseRef);
  if (!baseCommit) {
    console.error(`[ERROR] Cannot resolve reference: ${baseRef}`);
    console.error('Use a commit hash, tag name, or branch name.');
    const refs = getRecentRefs(resolvedPath);
    if (refs.tags.length > 0) {
      console.error(`\nAvailable tags: ${refs.tags.join(', ')}`);
    }
    if (refs.commits.length > 0) {
      console.error(`\nRecent commits:\n${refs.commits.map(c => `  ${c}`).join('\n')}`);
    }
    return 1;
  }

  const currentCommit = getCurrentCommit(resolvedPath);
  const shortBase = baseCommit.substring(0, 7);
  const shortCurrent = currentCommit ? currentCommit.substring(0, 7) : 'working';

  if (!options.json) {
    console.log(`\n[MUADDIB DIFF] Comparing ${shortBase} -> ${shortCurrent}\n`);
    console.log(`Base:    ${baseRef} (${shortBase})`);
    console.log(`Current: ${hasUncommittedChanges(resolvedPath) ? 'working directory (uncommitted changes)' : `HEAD (${shortCurrent})`}\n`);
  }

  let tempDir = null;
  let baseResult, currentResult;

  try {
    // Scan base commit
    if (!options.json) {
      console.log('[DIFF] Scanning base version...');
    }
    tempDir = createTempCopyAtCommit(resolvedPath, baseCommit);
    baseResult = await runSilentScan(tempDir, { paranoid: options.paranoid });
    cleanupTempDir(tempDir);
    tempDir = null;

    // Scan current version
    if (!options.json) {
      console.log('[DIFF] Scanning current version...');
    }
    currentResult = await runSilentScan(resolvedPath, { paranoid: options.paranoid });

  } catch (err) {
    if (tempDir) cleanupTempDir(tempDir);
    console.error(`[ERROR] Diff failed: ${err.message}`);
    return 1;
  }

  // Compare threats
  const comparison = compareThreats(
    baseResult.threats || [],
    currentResult.threats || []
  );

  const result = {
    base: {
      ref: baseRef,
      commit: baseCommit,
      threatsCount: baseResult.threats?.length || 0,
      riskScore: baseResult.summary?.riskScore || 0
    },
    current: {
      commit: currentCommit,
      hasUncommitted: hasUncommittedChanges(resolvedPath),
      threatsCount: currentResult.threats?.length || 0,
      riskScore: currentResult.summary?.riskScore || 0
    },
    diff: {
      added: comparison.added,
      removed: comparison.removed,
      unchanged: comparison.unchanged.length,
      scoreChange: (currentResult.summary?.riskScore || 0) - (baseResult.summary?.riskScore || 0)
    },
    timestamp: new Date().toISOString()
  };

  // Output
  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    // Summary
    console.log('\n' + '═'.repeat(60));
    console.log('                      DIFF SUMMARY');
    console.log('═'.repeat(60));

    const scoreChange = result.diff.scoreChange;
    const scoreIndicator = scoreChange > 0 ? `+${scoreChange}` : scoreChange.toString();
    const scoreColor = scoreChange > 0 ? 'worse' : scoreChange < 0 ? 'better' : 'same';

    console.log(`\n  Risk Score: ${result.base.riskScore} -> ${result.current.riskScore} (${scoreIndicator} ${scoreColor})`);
    console.log(`  Threats:    ${result.base.threatsCount} -> ${result.current.threatsCount}`);
    console.log(`\n  NEW threats:     ${comparison.added.length}`);
    console.log(`  REMOVED threats: ${comparison.removed.length}`);
    console.log(`  Unchanged:       ${comparison.unchanged.length}`);

    // New threats (the important part!)
    if (comparison.added.length > 0) {
      console.log('\n' + '─'.repeat(60));
      console.log('  NEW THREATS (introduced since ' + baseRef + ')');
      console.log('─'.repeat(60) + '\n');

      comparison.added.forEach((t, i) => {
        console.log(`  ${i + 1}. [${t.severity}] ${t.type}`);
        console.log(`     ${t.message}`);
        console.log(`     File: ${t.file}`);
        if (t.playbook) {
          console.log(`     Action: ${t.playbook}`);
        }
        console.log('');
      });
    } else {
      console.log('\n  [OK] No new threats introduced!\n');
    }

    // Removed threats (nice to know)
    if (comparison.removed.length > 0 && options.explain) {
      console.log('─'.repeat(60));
      console.log('  REMOVED THREATS (fixed since ' + baseRef + ')');
      console.log('─'.repeat(60) + '\n');

      comparison.removed.forEach((t, i) => {
        console.log(`  ${i + 1}. [${t.severity}] ${t.type} - ${t.file}`);
      });
      console.log('');
    }

    console.log('═'.repeat(60) + '\n');
  }

  // Return exit code based on new threats
  const failLevel = options.failLevel || 'high';
  const severityLevels = {
    critical: ['CRITICAL'],
    high: ['CRITICAL', 'HIGH'],
    medium: ['CRITICAL', 'HIGH', 'MEDIUM'],
    low: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  };

  const levelsToCheck = severityLevels[failLevel] || severityLevels.high;
  const newFailingThreats = comparison.added.filter(t => levelsToCheck.includes(t.severity));

  return newFailingThreats.length;
}

/**
 * Show available refs for comparison
 */
function showRefs(targetPath) {
  const resolvedPath = path.resolve(targetPath);

  if (!isGitRepo(resolvedPath)) {
    console.error('[ERROR] Not a git repository.');
    return;
  }

  const refs = getRecentRefs(resolvedPath, 15);

  console.log('\n[MUADDIB DIFF] Available references for comparison:\n');

  if (refs.tags.length > 0) {
    console.log('Tags:');
    refs.tags.forEach(t => console.log(`  - ${t}`));
    console.log('');
  }

  console.log('Recent commits:');
  refs.commits.forEach(c => console.log(`  - ${c}`));
  console.log('');

  console.log('Usage: muaddib diff <ref> [path]');
  console.log('Example: muaddib diff v1.2.0');
  console.log('Example: muaddib diff HEAD~5');
  console.log('Example: muaddib diff abc1234\n');
}

module.exports = {
  diff, showRefs, isGitRepo, getRecentRefs,
  // Exported for testing
  getThreatId, compareThreats, resolveRef, getCurrentCommit,
  hasUncommittedChanges, runSilentScan, SAFE_REF_REGEX
};
