'use strict';
// Behavioral tests of deploy/refresh-sandbox-image.sh: the script runs against a temporary git
// checkout with a fake `docker` (DOCKER=...) that records its calls and keeps the image label
// state, so the decision (rebuild or not, keep the previous image, survive a failed build) is
// observed from the outside.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { test, assert, addSkipped } = require('../test-utils');

const SCRIPT = path.join(__dirname, '..', '..', 'deploy', 'refresh-sandbox-image.sh');
const fwd = p => p.replace(/\\/g, '/');

const FAKE_DOCKER = `#!/usr/bin/env bash
S="$FAKE_DOCKER_STATE"
echo "$*" >> "$S/calls"
case "$1" in
  image)
    [ -f "$S/exists" ] || exit 1
    if [ "\${3:-}" = "--format" ]; then cat "$S/label" 2>/dev/null; echo; fi
    exit 0 ;;
  build)
    [ -f "$S/fail" ] && exit 1
    for a in "$@"; do case "$a" in muaddib.docker-tree=*) echo "\${a#muaddib.docker-tree=}" > "$S/candidate_label" ;; esac; done
    exit 0 ;;
  tag)
    if [ "$2" = "muaddib-sandbox:candidate" ]; then cp "$S/candidate_label" "$S/label"; touch "$S/exists"; fi
    exit 0 ;;
esac
exit 0
`;

function hasBash() {
  const r = spawnSync('bash', ['-c', 'echo ok'], { encoding: 'utf8' });
  return r.status === 0 && /ok/.test(r.stdout || '');
}

function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-refresh-'));
  const repo = path.join(dir, 'repo');
  const state = path.join(dir, 'state');
  fs.mkdirSync(path.join(repo, 'docker'), { recursive: true });
  fs.mkdirSync(state);
  fs.writeFileSync(path.join(repo, 'docker', 'Dockerfile'), 'FROM scratch\n');
  const git = (...a) => spawnSync('git', ['-C', repo, ...a], { encoding: 'utf8' });
  git('init', '-q');
  git('add', '-A');
  git('-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'x');
  const tree = git('rev-parse', 'HEAD:docker').stdout.trim();
  const fake = path.join(dir, 'fake-docker');
  fs.writeFileSync(fake, FAKE_DOCKER, { mode: 0o755 });
  return { dir, repo, state, tree, fake };
}

function run(env) {
  const log = path.join(env.dir, 'update.log');
  const r = spawnSync('bash', [fwd(SCRIPT), fwd(env.repo), fwd(log)], {
    encoding: 'utf8',
    env: { ...process.env, DOCKER: fwd(env.fake), FAKE_DOCKER_STATE: fwd(env.state) },
  });
  const calls = fs.existsSync(path.join(env.state, 'calls')) ? fs.readFileSync(path.join(env.state, 'calls'), 'utf8') : '';
  const label = fs.existsSync(path.join(env.state, 'label')) ? fs.readFileSync(path.join(env.state, 'label'), 'utf8').trim() : null;
  return { status: r.status, calls, label, log: fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '' };
}

function runRefreshSandboxImageTests() {
  console.log('\n=== REFRESH SANDBOX IMAGE TESTS ===\n');
  if (!hasBash()) { addSkipped('refresh-sandbox-image: bash not available'); return; }

  const cases = [];
  const withEnv = fn => () => { const env = setup(); cases.push(env.dir); fn(env); };

  test('SANDBOX-IMAGE: no image yet → built with the docker/ tree label, nothing kept as previous', withEnv(env => {
    const r = run(env);
    assert(r.status === 0, `exit 0 expected, got ${r.status} log=${r.log}`);
    assert(/build -q --label muaddib\.docker-tree=/.test(r.calls), 'a build must run, calls=' + r.calls);
    assert(r.label === env.tree, `image label must be the docker/ tree ${env.tree}, got ${r.label}`);
    assert(!/muaddib-sandbox:previous/.test(r.calls), 'no previous image to keep');
  }));

  test('SANDBOX-IMAGE: image built from the current docker/ tree → no rebuild', withEnv(env => {
    fs.writeFileSync(path.join(env.state, 'exists'), '');
    fs.writeFileSync(path.join(env.state, 'label'), env.tree + '\n');
    const r = run(env);
    assert(r.status === 0, `exit 0 expected, got ${r.status}`);
    assert(!/(^|\n)build /.test(r.calls), 'no build when the label matches, calls=' + r.calls);
  }));

  test('SANDBOX-IMAGE: stale or unlabelled image → rebuilt, previous kept for rollback', withEnv(env => {
    fs.writeFileSync(path.join(env.state, 'exists'), '');
    fs.writeFileSync(path.join(env.state, 'label'), '\n'); // e.g. an image built before labels existed
    const r = run(env);
    assert(r.status === 0, `exit 0 expected, got ${r.status} log=${r.log}`);
    assert(/tag muaddib-sandbox muaddib-sandbox:previous/.test(r.calls), 'the replaced image must be kept as :previous, calls=' + r.calls);
    assert(/tag muaddib-sandbox:candidate muaddib-sandbox/.test(r.calls), 'the candidate must be promoted');
    assert(r.label === env.tree, `label must now be the current tree, got ${r.label}`);
  }));

  test('SANDBOX-IMAGE: failed build → current image untouched, exit 1', withEnv(env => {
    fs.writeFileSync(path.join(env.state, 'exists'), '');
    fs.writeFileSync(path.join(env.state, 'label'), 'oldtree\n');
    fs.writeFileSync(path.join(env.state, 'fail'), '');
    const r = run(env);
    assert(r.status === 1, `exit 1 expected on build failure, got ${r.status}`);
    assert(!/(^|\n)tag /.test(r.calls), 'no tag after a failed build, calls=' + r.calls);
    assert(r.label === 'oldtree', `label must be unchanged, got ${r.label}`);
    assert(/build FAILED/.test(r.log), 'the failure must be logged');
  }));

  for (const d of cases) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ } }
}

module.exports = { runRefreshSandboxImageTests };
