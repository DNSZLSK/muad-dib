'use strict';

const fs = require('fs');
const path = require('path');

// ══════════════════════════════════════════════════════════════
// gVisor strace log parser
//
// gVisor's --strace flag logs syscalls at the kernel level in its
// debug log files. This parser extracts security-relevant data
// (file access, network connections, process execution) and returns
// the SAME structure as sandbox-runner.sh's strace/tcpdump parsing,
// so the downstream scoreFindings() analyzer needs no changes.
//
// gVisor strace format:
//   D0331 12:34:56.789012  1 strace.go:587] [  PID] process E syscall(args) = ret (dur)
//
// Or bare (without Go log prefix):
//   [  PID] process E syscall(args) = ret (dur)
// ══════════════════════════════════════════════════════════════

const SENSITIVE_PATTERN = /\.npmrc|\.ssh\/|\.aws\/|\.env(?:$|[^a-zA-Z])|\/etc\/passwd|\/etc\/shadow|\.gitconfig|\.bash_history/;

// Processes that are sandbox infrastructure — not spawned by the package
const SAFE_PROCESSES = new Set(['node', 'npm', 'npx', 'sh', 'git']);

// ── Line-level parsers ──

/**
 * Parse a single gVisor strace line.
 * Handles both Go-log-prefixed and bare formats.
 *
 * @param {string} line - Raw log line
 * @returns {object|null} Parsed syscall info or null if not a strace line
 */
function parseStraceLine(line) {
  // Strip Go log prefix if present: everything up to `] ` before the `[PID]` block
  const bracketIdx = line.indexOf('] [');
  const content = bracketIdx >= 0 ? line.substring(bracketIdx + 2).trim() : line.trim();

  // Match: [PID] process E/X syscall(args) = return (duration)
  const match = content.match(
    /^\[\s*(\d+)\]\s+(\S+)\s+[EX]\s+(\w+)\((.+)\)\s*=\s*(.+?)(?:\s+\([\d.]+[µm]?s\))?$/
  );
  if (!match) return null;

  return {
    pid: parseInt(match[1], 10),
    process: match[2],
    syscall: match[3],
    args: match[4],
    returnValue: match[5].trim()
  };
}

/**
 * Extract file path and flags from openat/open args.
 * gVisor format: AT_FDCWD, "/path", O_RDONLY|O_CLOEXEC
 *
 * @param {string} args - Syscall arguments string
 * @returns {object|null} { path, flags } or null
 */
function extractOpenatPath(args) {
  // Comma-separated: AT_FDCWD, "/path/to/file", O_RDONLY|O_CLOEXEC, 0o0
  const match = args.match(/"([^"]+)"[\s,]+([A-Z_|]+)/);
  if (match) return { path: match[1], flags: match[2] };

  // Space-separated (some gVisor versions): AT_FDCWD "/path" O_RDONLY
  const matchSpace = args.match(/"([^"]+)"\s+([A-Z_|]+)/);
  if (matchSpace) return { path: matchSpace[1], flags: matchSpace[2] };

  return null;
}

/**
 * Extract IP and port from connect() args.
 * gVisor format: {Family: AF_INET, Addr: 1.2.3.4, Port: 443}
 *
 * @param {string} args - Syscall arguments string
 * @returns {object|null} { ip, port } or null
 */
function extractConnectInfo(args) {
  const match = args.match(/\{Family:\s*AF_INET,\s*Addr:\s*([\d.]+),\s*Port:\s*(\d+)\}/);
  if (!match) return null;
  return { ip: match[1], port: parseInt(match[2], 10) };
}

/**
 * Extract command path from execve() args.
 * gVisor format: execve("/usr/bin/curl", ["curl", ...], ...)
 *
 * @param {string} args - Syscall arguments string
 * @returns {string|null} Command path or null
 */
function extractExecveCommand(args) {
  const match = args.match(/^"([^"]+)"/);
  return match ? match[1] : null;
}

// ── Main parser ──

/**
 * Parse gVisor strace log content and extract security-relevant findings.
 * Returns the SAME data structure as sandbox-runner.sh's strace parsing
 * so scoreFindings() works identically.
 *
 * @param {string} content - Raw gVisor strace log content
 * @returns {object} { sensitive_files: {read, written}, network: {http_connections}, processes: {spawned} }
 */
function parseGvisorStrace(content) {
  const sensitiveReads = new Set();
  const sensitiveWrites = new Set();
  const connections = new Map();  // dedup by ip:port
  const processes = new Map();    // dedup by pid:command

  const lines = content.split('\n');

  for (const line of lines) {
    const parsed = parseStraceLine(line);
    if (!parsed) continue;

    // Only process successful syscalls (return >= 0)
    if (parsed.returnValue.startsWith('-')) continue;

    switch (parsed.syscall) {
      case 'openat':
      case 'open': {
        const info = extractOpenatPath(parsed.args);
        if (!info || !SENSITIVE_PATTERN.test(info.path)) break;

        if (/O_WRONLY|O_RDWR|O_CREAT/.test(info.flags)) {
          sensitiveWrites.add(info.path);
        } else if (/O_RDONLY/.test(info.flags)) {
          sensitiveReads.add(info.path);
        }
        break;
      }

      case 'connect': {
        const conn = extractConnectInfo(parsed.args);
        if (!conn) break;
        if (conn.ip.startsWith('127.')) break;  // skip loopback
        if (conn.port === 65535) break;          // skip probe port
        const key = `${conn.ip}:${conn.port}`;
        if (!connections.has(key)) {
          connections.set(key, { host: conn.ip, port: conn.port, protocol: 'TCP' });
        }
        break;
      }

      case 'execve': {
        const cmd = extractExecveCommand(parsed.args);
        if (!cmd) break;
        const basename = path.basename(cmd);
        if (SAFE_PROCESSES.has(basename)) break;
        const key = `${parsed.pid}:${cmd}`;
        if (!processes.has(key)) {
          processes.set(key, { command: cmd, pid: parsed.pid });
        }
        break;
      }
    }
  }

  return {
    sensitive_files: {
      read: [...sensitiveReads],
      written: [...sensitiveWrites]
    },
    network: {
      http_connections: [...connections.values()]
    },
    processes: {
      spawned: [...processes.values()]
    }
  };
}

// ── Log discovery ──

/**
 * Find gVisor log files for a specific container.
 * Searches the debug-log directory using multiple strategies:
 *   1. %ID% template → directory named after full container ID
 *   2. Truncated ID (12 chars) directory
 *   3. Files in logDir containing the container ID
 *
 * @param {string} containerId - Docker container ID (full 64-char or truncated)
 * @param {string} logDir - gVisor debug-log base directory (default: /tmp/runsc)
 * @returns {string[]} Matching log file paths
 */
function findGvisorLogs(containerId, logDir) {
  logDir = logDir || '/tmp/runsc';
  const logFiles = [];

  if (!fs.existsSync(logDir)) return logFiles;

  const shortId = containerId.substring(0, 12);

  // Strategy 1: directory named after full container ID (%ID% template)
  const fullDir = path.join(logDir, containerId);
  if (fs.existsSync(fullDir) && fs.statSync(fullDir).isDirectory()) {
    return collectLogFiles(fullDir);
  }

  // Strategy 2: directory named after truncated ID
  const shortDir = path.join(logDir, shortId);
  if (fs.existsSync(shortDir) && fs.statSync(shortDir).isDirectory()) {
    return collectLogFiles(shortDir);
  }

  // Strategy 3: flat files containing the container ID in name
  try {
    const files = fs.readdirSync(logDir);
    for (const file of files) {
      if ((file.includes(containerId) || file.includes(shortId)) &&
          (file.endsWith('.log') || file.includes('boot'))) {
        logFiles.push(path.join(logDir, file));
      }
    }
  } catch { /* directory not readable */ }

  return logFiles;
}

function collectLogFiles(dir) {
  const files = [];
  try {
    for (const file of fs.readdirSync(dir)) {
      if (file.endsWith('.log') || file.includes('boot')) {
        files.push(path.join(dir, file));
      }
    }
  } catch { /* directory not readable */ }
  return files;
}

// ── Aggregated parser (main entry point) ──

/**
 * Parse gVisor log file and return report-compatible structure.
 * This is the main export matching the spec:
 *   parseGvisorLog(logPath) → same format as parseStraceOutput()
 *
 * @param {string} logPath - Path to a gVisor strace log file
 * @returns {object} Report supplement with sensitive_files, network, processes
 */
function parseGvisorLog(logPath) {
  try {
    const content = fs.readFileSync(logPath, 'utf8');
    return parseGvisorStrace(content);
  } catch {
    return {
      sensitive_files: { read: [], written: [] },
      network: { http_connections: [] },
      processes: { spawned: [] }
    };
  }
}

/**
 * Parse all gVisor logs for a container and return aggregated report supplement.
 *
 * @param {string} containerId - Docker container ID
 * @param {string} logDir - gVisor debug-log base directory
 * @returns {object} Aggregated report supplement
 */
function parseGvisorLogs(containerId, logDir) {
  const emptyResult = {
    sensitive_files: { read: [], written: [] },
    network: { http_connections: [] },
    processes: { spawned: [] }
  };

  const logFiles = findGvisorLogs(containerId, logDir);
  if (logFiles.length === 0) return emptyResult;

  // Aggregate across all log files (boot, gofer, etc.)
  const allReads = new Set();
  const allWrites = new Set();
  const allConnections = new Map();
  const allProcesses = new Map();

  for (const logFile of logFiles) {
    const result = parseGvisorLog(logFile);

    for (const f of result.sensitive_files.read) allReads.add(f);
    for (const f of result.sensitive_files.written) allWrites.add(f);
    for (const c of result.network.http_connections) {
      const key = `${c.host}:${c.port}`;
      if (!allConnections.has(key)) allConnections.set(key, c);
    }
    for (const p of result.processes.spawned) {
      const key = `${p.pid}:${p.command}`;
      if (!allProcesses.has(key)) allProcesses.set(key, p);
    }
  }

  return {
    sensitive_files: { read: [...allReads], written: [...allWrites] },
    network: { http_connections: [...allConnections.values()] },
    processes: { spawned: [...allProcesses.values()] }
  };
}

/**
 * Clean up gVisor log files for a container after analysis.
 * Prevents disk fill from accumulated logs across sandbox runs.
 *
 * @param {string} containerId - Docker container ID
 * @param {string} logDir - gVisor debug-log base directory
 */
function cleanupGvisorLogs(containerId, logDir) {
  logDir = logDir || '/tmp/runsc';
  const shortId = containerId.substring(0, 12);

  try {
    // Try container-specific directory first
    for (const dirName of [containerId, shortId]) {
      const dir = path.join(logDir, dirName);
      if (fs.existsSync(dir) && fs.statSync(dir).isDirectory()) {
        fs.rmSync(dir, { recursive: true, force: true });
        return;
      }
    }

    // Fall back to individual files
    const files = fs.readdirSync(logDir);
    for (const file of files) {
      if (file.includes(containerId) || file.includes(shortId)) {
        fs.unlinkSync(path.join(logDir, file));
      }
    }
  } catch { /* cleanup is best-effort */ }
}

module.exports = {
  parseGvisorLog,
  parseGvisorLogs,
  parseGvisorStrace,
  findGvisorLogs,
  cleanupGvisorLogs,
  // Exported for unit tests
  parseStraceLine,
  extractOpenatPath,
  extractConnectInfo,
  extractExecveCommand
};
