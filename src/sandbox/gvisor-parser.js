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

const fs = require('fs');
const path = require('path');

// Where runsc writes its trace logs (--debug-log=<dir>/%ID%/) and where the host reads them.
// Not under /tmp: the monitor runs with PrivateTmp=true, so a host /tmp/runsc written by the
// Docker daemon is invisible to it. MUADDIB_GVISOR_LOG_DIR overrides; install-gvisor.sh and
// daemon.json must use the same directory.
const DEFAULT_GVISOR_LOG_DIR = '/var/log/runsc';
function gvisorLogDir() {
  return process.env.MUADDIB_GVISOR_LOG_DIR || DEFAULT_GVISOR_LOG_DIR;
}

// ══════════════════════════════════════════════════════════════
// gVisor strace log parser
//
// runsc --strace writes one line per syscall enter (E) and exit (X) in the boot log.
// Format, taken from real runsc release-20260323.0 traces (tests/samples/gvisor/) and
// pkg/sentry/strace + pkg/sentry/kernel/task_log.go of that release:
//
//   I1121 23:46:30.140447       1 strace.go:605] [  11:  11] npm install exp X connect(
//     0x15 socket:[24], 0x7efd... {Family: AF_INET, Addr: 104.16.10.34, Port: 443}, 0x10)
//     = 0 (0x0) errno=115 (operation now in progress) (77.1µs)
//
// - prefix "[ tgid: tid]" (nested PID namespaces: "[ root(ns): root(ns)]");
// - then the task name (comm, at most 15 bytes, set by the process itself: it can hold
//   spaces, e.g. "npm install exp", or text that imitates the rest of the line);
// - paths are NOT quoted ("AT_FDCWD /cwd, 0x7f.. /etc/passwd, O_RDONLY|O_CLOEXEC, 0o0");
// - a failed syscall still prints "= 0 (0x0)" followed by "errno=N (text)": success is
//   "no errno", never "return value >= 0".
//
// The whole container is traced, runner included (su reads /etc/shadow, the runner
// writes the honeytokens, npm reads ~/.npmrc). Only the processes the runner starts for
// the package are analyzed: the subtrees whose root is a shell exec'd by a child of `su`
// (`su sandboxuser -s /bin/sh -c "npm install ..."` and the entry point), found through
// the clone/clone3/fork/vfork exits. runsc must trace those syscalls
// (--strace-syscalls=openat,open,connect,execve,execveat,clone,clone3,fork,vfork);
// without them the scope is unknown and the run is reported as unusable, not clean.
// ══════════════════════════════════════════════════════════════

// `.env` must start a path component (.env, .env.local): process.env.js is a module, not
// a dotenv file.
const SENSITIVE_PATTERN = /\.npmrc|\.ssh\/|\.aws\/|(?:^|\/)\.env(?:$|[^a-zA-Z])|\/etc\/passwd|\/etc\/shadow|\.gitconfig|\.bash_history/;

// The root npm writes every file of every package it installs (tarball extraction, in its
// own process). A sensitive-looking name it writes under node_modules is a published file,
// not package behavior; package code writes from install-script processes, and an npm an
// install script starts is not the root npm. The path is normalized first, so a
// node_modules/../ path does not get the exemption.
const isRootNpmExtraction = (p) => path.posix.normalize(p).includes('/node_modules/');

// Processes that are sandbox infrastructure — not spawned by the package
const SAFE_PROCESSES = new Set(['node', 'npm', 'npx', 'sh', 'git']);

const TRACED_SYSCALLS = new Set(['openat', 'open', 'connect', 'execve', 'execveat', 'clone', 'clone3', 'fork', 'vfork']);
const CLONE_SYSCALLS = new Set(['clone', 'clone3', 'fork', 'vfork']);
const SHELLS = new Set(['sh', 'ash', 'dash', 'bash']);
// The comm is at most 15 bytes (TASK_COMM_LEN - 1), so the real " E|X syscall(" marker
// starts at most 16 characters after the "] " that closes the task prefix.
const MAX_COMM = 15;
// Paths are at most PATH_MAX (4096) bytes: an exec path cannot extend past this.
const MAX_PATH_SPAN = 4200;
// Exec split candidates tried before failing closed (a real line has exactly one).
const MAX_EXEC_SPLITS = 8;
const MARKER_RE = / ([EX]) ([a-z0-9_]+)\(/g;

// Every line holds text the sandboxed package chose (paths, argv, task name) and is parsed
// synchronously on the monitor's main thread: no backtracking regex, linear scans only.

/** Digits of one prefix field ("  11" or "   1(  7)" in nested PID namespaces). */
function prefixNumber(field) {
  const f = field.trim();
  const paren = f.indexOf('(');
  const n = (paren >= 0 ? f.slice(0, paren) : f).trim();
  return /^\d{1,10}$/.test(n) ? parseInt(n, 10) : null;
}

/** End index (exclusive) of a Go %q string list "[...]" starting at s[i] === '[', or -1. */
function goListEnd(s, i) {
  if (s[i] !== '[') return -1;
  i++;
  if (s[i] === ']') return i + 1;
  for (;;) {
    if (s[i] !== '"') return -1;
    i++;
    while (i < s.length && s[i] !== '"') i += s[i] === '\\' ? 2 : 1;
    if (i >= s.length) return -1;
    i++; // closing quote
    if (s[i] === ']') return i + 1;
    if (s[i] !== ',' || s[i + 1] !== ' ') return -1;
    i += 2;
  }
}

/** End index of "0x<hex>" at s[i], or -1. */
function hexEnd(s, i) {
  if (s[i] !== '0' || s[i + 1] !== 'x') return -1;
  let j = i + 2;
  while (j < s.length && /[0-9a-f]/.test(s[j])) j++;
  return j > i + 2 ? j : -1;
}

// ── Line-level parsers ──

/**
 * Parse one runsc strace line.
 * @param {string} line
 * @returns {null|{tgid:number, tid:number, comm:string, phase:'E'|'X', syscall:string,
 *   args:string, ret:number|null, errno:number|null}}
 */
function parseStraceLine(line) {
  // Task prefix "[ tgid: tid] " right after the glog header "...strace.go:NNN] ".
  const header = line.indexOf('] [');
  const start = header >= 0 ? header + 2 : (line[0] === '[' ? 0 : -1);
  if (start < 0) return null;
  const close = line.indexOf('] ', start);
  if (close < 0 || close - start > 48) return null;
  const fields = line.slice(start + 1, close).split(':');
  if (fields.length !== 2) return null;
  const tgid = prefixNumber(fields[0]), tid = prefixNumber(fields[1]);
  if (tgid === null || tid === null) return null;
  const rest = line.slice(close + 2);
  // Last marker that still fits after a <= 15-byte comm: a comm that imitates
  // " X openat(" sits before the real marker, never after it.
  const head = rest.slice(0, MAX_COMM + 32);
  let marker = null;
  MARKER_RE.lastIndex = 0;
  let m;
  while ((m = MARKER_RE.exec(head)) !== null) {
    if (m.index > MAX_COMM) break;
    if (m.index >= 1 && TRACED_SYSCALLS.has(m[2])) marker = { index: m.index, phase: m[1], syscall: m[2], end: m.index + m[0].length };
    MARKER_RE.lastIndex = m.index + 1;
  }
  if (!marker) return null;
  let body = rest.slice(marker.end);
  let ret = null, errno = null;
  if (marker.phase === 'X') {
    // "... ) = <ret> (0x<ret>)[ errno=<n> (<text>)] (<duration>)" is the end of the line;
    // the args before it can contain anything, so it is read from the last ") = ".
    const k = body.lastIndexOf(') = ');
    if (k < 0) return null;
    let t = body.slice(k + 4);
    const r = /^(-?\d{1,20}) \(0x[0-9a-f]{1,16}\)/.exec(t);
    if (!r) return null;
    ret = parseInt(r[1], 10);
    t = t.slice(r[0].length);
    if (t.startsWith(' errno=')) {
      const e = /^ errno=(\d{1,5}) \(/.exec(t);
      const closeText = e ? t.indexOf(')', e[0].length) : -1;
      if (closeText < 0) return null;
      errno = parseInt(e[1], 10);
      t = t.slice(closeText + 1);
    }
    if (!/^ \([^)]{0,32}\)$/.test(t)) return null;
    body = body.slice(0, k);
  } else {
    if (!body.endsWith(')')) return null;
    body = body.slice(0, -1);
  }
  return { tgid, tid, comm: rest.slice(0, marker.index), phase: marker.phase, syscall: marker.syscall, args: body, ret, errno };
}

/**
 * openat/open args: "<dirfd>, 0x<addr> <path>, <flags>, <mode>" (open has no dirfd).
 * The path is unquoted and may contain ", ": flags and mode are peeled off the right,
 * the path is what follows the last "0x<addr> " pointer. For a relative path the
 * directory name of the fd is prepended, so openat(<fd of ~/.ssh>, "id_rsa") is
 * still seen as ~/.ssh/id_rsa.
 * @returns {null|{path:string, flags:string}}
 */
function extractOpenatPath(args, syscall = 'openat') {
  const modeCut = args.lastIndexOf(', ');
  if (modeCut < 0) return null;
  const head = args.slice(0, modeCut);
  const flagsCut = head.lastIndexOf(', ');
  if (flagsCut < 0) return null;
  const flags = head.slice(flagsCut + 2);
  if (!flags.split('|').every(tok => /^O_[A-Z_]{1,24}$/.test(tok) || /^0x[0-9a-f]{1,16}$/.test(tok))) return null;
  const fdAndPath = head.slice(0, flagsCut);
  const ptr = /(?:^|, )0x[0-9a-f]+ /g;
  let last = null, m;
  while ((m = ptr.exec(fdAndPath)) !== null) {
    if (syscall === 'open' || m.index > 0) last = m;
    ptr.lastIndex = m.index + 1;
  }
  if (!last) return null;
  let p = fdAndPath.slice(last.index + last[0].length);
  if (!p) return null;
  if (!p.startsWith('/') && syscall === 'openat') {
    const fd = fdAndPath.slice(0, last.index);
    const sp = fd.indexOf(' ');
    const dir = sp > 0 && (fd.slice(0, sp) === 'AT_FDCWD' || hexEnd(fd, 0) === sp) ? fd.slice(sp + 1) : '';
    if (dir.startsWith('/')) p = dir.replace(/\/$/, '') + '/' + p;
  }
  return { path: p, flags };
}

/**
 * connect args: "<fd>, 0x<addr> {Family: AF_INET, Addr: 1.2.3.4, Port: 443}, 0x10".
 * IPv4 only (the sandbox bridge has no IPv6 route).
 * @returns {null|{ip:string, port:number}}
 */
function extractConnectInfo(args) {
  const match = args.match(/\{Family: AF_INET, Addr: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}), Port: (\d{1,5})\}/);
  if (!match) return null;
  return { ip: match[1], port: parseInt(match[2], 10) };
}

/**
 * execve args: "0x<addr> <path>, 0x<addr> ["argv0", ...], 0x<addr> ["ENV=..", ...]"
 * (execveat: "<fd>, 0x<addr> <path>, ...argv, envp, 0x<flags>"). The path is unquoted
 * and may itself contain ", 0x1 [": the split kept is the one whose remainder parses as
 * the two Go-quoted vectors, so a binary named "/tmp/node, 0x1 [x" is not read as node.
 * At most MAX_EXEC_SPLITS candidates are checked; past that the longest candidate path is
 * kept (fail closed: it does not read as a known program).
 * @returns {null|{path:string, argv:string[]}}
 */
function extractExecveCommand(args, syscall = 'execve') {
  let s = args;
  if (syscall === 'execveat') {
    const cut = s.indexOf(', 0x');
    if (cut < 0) return null;
    s = s.slice(cut + 2);
  }
  const lead = hexEnd(s, 0);
  if (lead < 0 || s[lead] !== ' ') return null;
  s = s.slice(lead + 1);
  const sep = /, 0x[0-9a-f]+ \[/g;
  let m, tries = 0, lastCandidate = -1;
  while ((m = sep.exec(s)) !== null && m.index <= MAX_PATH_SPAN) {
    lastCandidate = m.index;
    if (tries++ < MAX_EXEC_SPLITS) {
      const argvStart = m.index + m[0].length - 1;
      const argvEnd = goListEnd(s, argvStart);
      if (argvEnd > 0 && s.startsWith(', 0x', argvEnd)) {
        const envHex = hexEnd(s, argvEnd + 2);
        const envEnd = envHex > 0 && s[envHex] === ' ' ? goListEnd(s, envHex + 1) : -1;
        const flagsEnd = envEnd > 0 && s.startsWith(', ', envEnd) ? hexEnd(s, envEnd + 2) : envEnd;
        if (envEnd > 0 && flagsEnd === s.length) {
          let argv;
          try { argv = JSON.parse(s.slice(argvStart, argvEnd)); } catch { argv = []; }
          return { path: s.slice(0, m.index), argv };
        }
      }
    }
    sep.lastIndex = m.index + 1;
  }
  return lastCandidate >= 0 ? { path: s.slice(0, lastCandidate), argv: [] } : null;
}

// ── Main parser ──

function emptySupplement() {
  return {
    sensitive_files: { read: [], written: [] },
    network: { http_connections: [] },
    processes: { spawned: [] }
  };
}

/**
 * Parse one runsc boot log and extract what the package's processes did.
 * Returns the report supplement consumed by scoreFindings() plus:
 *   straceLines: syscall lines recognized (0 on a non-empty log = unknown format);
 *   scoped: true when at least one package subtree (child of su) was found.
 */
function parseGvisorStrace(content) {
  const out = emptySupplement();
  const events = [];
  const children = new Map();   // tgid -> [{ child, index }] (successful clone/fork exits)
  const cloneIndex = new Map(); // child tgid -> index of the clone exit that created it
  const parentOf = new Map();   // child tgid -> parent tgid
  const execs = new Map();      // tgid -> [{ index, path, argv }] (execs that took effect, in order)
  const lastExecOfTid = new Map(); // tid -> exec record, while that tid's last event is an exec
  const superseded = new Set(); // event indexes of exec attempts that did not take effect

  // Pass 1: syscall exits (they carry the result), clones and execs.
  for (const line of content.split('\n')) {
    if (line.indexOf(' X ') < 0) continue;
    const ev = parseStraceLine(line);
    if (!ev || ev.phase !== 'X') continue;
    const index = events.length;
    events.push(ev);
    const isExec = ev.syscall === 'execve' || ev.syscall === 'execveat';
    // runsc release-20260323.0 prints a FAILED execve as "= 0 (0x0)" with no errno (real
    // trace: env's PATH search /usr/local/sbin/node ... /usr/bin/node, four "= 0" exits).
    // A thread whose execve worked runs the new image before its next exec; consecutive
    // execs of one thread are attempts, and only the last one can have taken effect.
    const pending = lastExecOfTid.get(ev.tid);
    if (pending && isExec) {
      superseded.add(pending.index);
      const list = execs.get(pending.tgid);
      if (list && list[list.length - 1] === pending) list.pop();
    }
    lastExecOfTid.delete(ev.tid);
    if (CLONE_SYSCALLS.has(ev.syscall)) {
      if (ev.errno === null && ev.ret > 0) {
        if (!children.has(ev.tgid)) children.set(ev.tgid, []);
        children.get(ev.tgid).push({ child: ev.ret, index });
        if (!parentOf.has(ev.ret)) { parentOf.set(ev.ret, ev.tgid); cloneIndex.set(ev.ret, index); }
      }
    } else if ((ev.syscall === 'execve' || ev.syscall === 'execveat') && ev.errno === null) {
      const cmd = extractExecveCommand(ev.args, ev.syscall);
      if (cmd) {
        if (!execs.has(ev.tgid)) execs.set(ev.tgid, []);
        const rec = { index, tgid: ev.tgid, path: cmd.path, argv: cmd.argv };
        execs.get(ev.tgid).push(rec);
        lastExecOfTid.set(ev.tid, rec);
      }
    }
  }

  // Program image of a process just before event `index`: its last exec before it, else
  // the parent's image when it was cloned (independent of the order lines were written).
  const imageAt = (tgid, index, depth = 0) => {
    const list = execs.get(tgid) || [];
    for (let i = list.length - 1; i >= 0; i--) if (list[i].index < index) return path.basename(list[i].path);
    if (depth > 64 || !parentOf.has(tgid)) return null;
    return imageAt(parentOf.get(tgid), cloneIndex.get(tgid), depth + 1);
  };

  // Roots: a shell exec'd by a process whose image is su - the su child (util-linux su
  // forks) or su itself (busybox su, in the sandbox image, execs the shell in place).
  const rootStart = new Map();
  for (const [t, list] of execs) {
    for (const e of list) {
      if (SHELLS.has(path.basename(e.path)) && imageAt(t, e.index) === 'su') {
        if (!rootStart.has(t) || e.index < rootStart.get(t)) rootStart.set(t, e.index);
      }
    }
  }

  // Package subtrees: the root from its shell exec, and every process it then clones.
  const inScope = new Map(); // tgid -> first event index that belongs to the package
  for (const [root, start] of rootStart) {
    const queue = [[root, start]];
    while (queue.length) {
      const [t, from] = queue.shift();
      if (inScope.has(t) && inScope.get(t) <= from) continue;
      inScope.set(t, from);
      for (const c of children.get(t) || []) if (c.index >= from) queue.push([c.child, from]);
    }
  }

  // The npm CLI started by a root shell reads ~/.npmrc and ~/.gitconfig (both honeytokens;
  // .gitconfig seen in a production trace, npm 11) on every install: those reads are npm's
  // own config load, not the package. Only that npm is exempt (the root
  // itself when the shell execs npm in place, or a direct child of the root); an npm
  // started by an install script (`npm config get ...` reads the token for the script)
  // is not.
  const isNpm = (e) => path.basename(e.path) === 'npm' || /(?:^|\/)npm(?:-cli\.js)?$/.test(e.argv[1] || '');
  const rootNpm = new Set();
  for (const [t, list] of execs) {
    const fromRoot = rootStart.has(t) || rootStart.has(parentOf.get(t));
    if (fromRoot && list.some(e => (!rootStart.has(t) || e.index > rootStart.get(t)) && isNpm(e))) rootNpm.add(t);
  }

  const reads = new Set(), writes = new Set(), conns = new Map(), procs = new Map();
  events.forEach((ev, index) => {
    if (!inScope.has(ev.tgid) || index < inScope.get(ev.tgid)) return;
    if (ev.errno !== null) return; // failed: no access happened (EINPROGRESS handled below)
    switch (ev.syscall) {
      case 'openat':
      case 'open': {
        const info = extractOpenatPath(ev.args, ev.syscall);
        if (!info || !SENSITIVE_PATTERN.test(info.path)) break;
        if (/O_WRONLY|O_RDWR|O_CREAT/.test(info.flags)) {
          if (!(rootNpm.has(ev.tgid) && isRootNpmExtraction(info.path))) writes.add(info.path);
        }
        else if (!(rootNpm.has(ev.tgid) && /(?:^|\/)(?:\.?npmrc|\.gitconfig)$/.test(info.path))) reads.add(info.path);
        break;
      }
      case 'execve':
      case 'execveat': {
        if (superseded.has(index)) break; // exec attempt that did not take effect
        const cmd = extractExecveCommand(ev.args, ev.syscall);
        if (!cmd || SAFE_PROCESSES.has(path.basename(cmd.path))) break;
        const key = `${ev.tgid}:${cmd.path}`;
        if (!procs.has(key)) procs.set(key, { command: cmd.path, pid: ev.tgid });
        break;
      }
    }
  });
  // connect: a non-blocking connect returns errno=115 (EINPROGRESS) - that IS the attempt.
  events.forEach((ev, index) => {
    if (ev.syscall !== 'connect' || !inScope.has(ev.tgid) || index < inScope.get(ev.tgid)) return;
    if (ev.errno !== null && ev.errno !== 115) return;
    const conn = extractConnectInfo(ev.args);
    if (!conn || conn.ip.startsWith('127.') || conn.port === 65535) return;
    const key = `${conn.ip}:${conn.port}`;
    if (!conns.has(key)) conns.set(key, { host: conn.ip, port: conn.port, protocol: 'TCP' });
  });

  out.sensitive_files.read = [...reads];
  out.sensitive_files.written = [...writes];
  out.network.http_connections = [...conns.values()];
  out.processes.spawned = [...procs.values()];
  out.straceLines = events.length;
  out.scoped = rootStart.size > 0;
  return out;
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
 * @param {string} logDir - gVisor debug-log base directory (default: DEFAULT_GVISOR_LOG_DIR)
 * @returns {string[]} Matching log file paths
 */
function findGvisorLogs(containerId, logDir) {
  logDir = logDir || DEFAULT_GVISOR_LOG_DIR;
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
    const result = parseGvisorStrace(content);
    result.nonEmpty = content.trim().length > 0;
    return result;
  } catch {
    return Object.assign(emptySupplement(), { straceLines: 0, scoped: false, nonEmpty: false });
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
  // logFiles: how many runsc trace logs were found for this container. 0 means the
  // runtime produced no trace at all (runsc started without --strace/--debug-log), so
  // the empty sections below are an ABSENCE of telemetry, not an observation of nothing.
  // unusable: logs were found but cannot be trusted as an observation - no syscall line
  // recognized in a non-empty log (unknown runsc format: an empty result would read as a
  // clean run), or no package process tree (clone/fork not traced, or no su child).
  const emptyResult = Object.assign(emptySupplement(), { logFiles: 0, straceLines: 0, scoped: false, unusable: null });

  const logFiles = findGvisorLogs(containerId, logDir);
  if (logFiles.length === 0) return emptyResult;

  // Aggregate across all log files (boot, gofer, etc.)
  const allReads = new Set();
  const allWrites = new Set();
  const allConnections = new Map();
  const allProcesses = new Map();
  let straceLines = 0, scoped = false, nonEmpty = false;

  for (const logFile of logFiles) {
    const result = parseGvisorLog(logFile);
    straceLines += result.straceLines || 0;
    scoped = scoped || !!result.scoped;
    nonEmpty = nonEmpty || !!result.nonEmpty;

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
    processes: { spawned: [...allProcesses.values()] },
    logFiles: logFiles.length,
    straceLines,
    scoped,
    unusable: straceLines === 0
      ? (nonEmpty ? 'runsc trace log present but no syscall line recognized (unknown runsc strace format)' : 'runsc trace log is empty')
      : (scoped ? null : 'runsc trace has no package process tree (clone/fork not in --strace-syscalls, or no su child)')
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
  logDir = logDir || DEFAULT_GVISOR_LOG_DIR;
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
  gvisorLogDir,
  DEFAULT_GVISOR_LOG_DIR,
  TRACED_SYSCALLS,
  // Exported for unit tests
  parseStraceLine,
  extractOpenatPath,
  extractConnectInfo,
  extractExecveCommand
};
