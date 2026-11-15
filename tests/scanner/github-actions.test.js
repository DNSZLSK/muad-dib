const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert, cleanupTemp, runScanDirect } = require('../test-utils');

const { scanGitHubActions } = require('../../src/scanner/github-actions.js');

function makeTempWorkflow(yamlContent, fileName = 'ci.yml') {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-gha-'));
  const workflowDir = path.join(tmp, '.github', 'workflows');
  fs.mkdirSync(workflowDir, { recursive: true });
  fs.writeFileSync(path.join(workflowDir, fileName), yamlContent);
  return tmp;
}

function makeTempAction(yamlContent, fileName = 'action.yml') {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-gha-'));
  const actionDir = path.join(tmp, '.github', 'actions', 'my-action');
  fs.mkdirSync(actionDir, { recursive: true });
  fs.writeFileSync(path.join(actionDir, fileName), yamlContent);
  return tmp;
}

async function runGitHubActionsTests() {
  console.log('\n=== GITHUB ACTIONS TESTS ===\n');

  // --- workflow_injection detection ---

  // Scope: an expression is an injection only where it is expanded into executed code.
  const inScope = (yamlText, maker = makeTempWorkflow) => {
    const tmp = maker(yamlText);
    try { return scanGitHubActions(tmp).some(t => t.type === 'workflow_injection'); } finally { cleanupTemp(tmp); }
  };

  test('GHA: event context passed through env: and quoted in run is NOT an injection (documented mitigation)', () => {
    assert(!inScope(`
on: issue_comment
jobs:
  parse:
    runs-on: ubuntu-latest
    steps:
      - env:
          CONFIRM_BODY: \${{ github.event.comment.body }}
          TITLE: \${{ github.event.issue.title }}
        run: |
          printf '%s' "$CONFIRM_BODY" > /tmp/body.txt
          echo "$TITLE"
`), 'env-passed context must not be reported');
  });

  test('GHA: event context as an input of a non-script action is NOT an injection', () => {
    assert(!inScope(`
on: issue_comment
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions-ecosystem/action-add-labels@v1
        with:
          labels: \${{ github.event.comment.body }}
`), 'action input must not be reported');
  });

  test('GHA: event context in actions/github-script script: IS an injection', () => {
    assert(inScope(`
on: issue_comment
jobs:
  js:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            const body = "\${{ github.event.comment.body }}";
`), 'github-script interpolation must be reported');
  });

  test('GHA: event context in a composite action run: IS an injection', () => {
    assert(inScope(`
name: my-action
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "\${{ github.event.issue.title }}"
`, makeTempAction), 'composite run interpolation must be reported');
  });

  test('GHA: an unparsable workflow keeps the whole-file match (fail toward detection)', () => {
    assert(inScope('on: [issue_comment\njobs: {{{\n  run: echo ${{ github.event.comment.body }}\n'), 'broken YAML must still be matched');
  });

  test('GHA: Detects ${{ github.event.comment.body }} injection', () => {
    const tmp = makeTempWorkflow(`
name: PR Comment
on: issue_comment
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo \${{ github.event.comment.body }}
`);
    try {
      const threats = scanGitHubActions(tmp);
      const t = threats.find(t => t.type === 'workflow_injection');
      assert(t, 'Should detect workflow injection via comment.body');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  test('GHA: Detects ${{ github.event.issue.title }} injection', () => {
    const tmp = makeTempWorkflow(`
name: Issue Handler
on: issues
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: echo \${{ github.event.issue.title }}
`);
    try {
      const threats = scanGitHubActions(tmp);
      const t = threats.find(t => t.type === 'workflow_injection');
      assert(t, 'Should detect workflow injection via issue.title');
    } finally { cleanupTemp(tmp); }
  });

  test('GHA: Detects ${{ github.event.pull_request.body }} injection', () => {
    const tmp = makeTempWorkflow(`
name: PR Handler
on: pull_request_target
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: echo \${{ github.event.pull_request.body }}
`);
    try {
      const threats = scanGitHubActions(tmp);
      const t = threats.find(t => t.type === 'workflow_injection');
      assert(t, 'Should detect workflow injection via pull_request.body');
    } finally { cleanupTemp(tmp); }
  });

  test('GHA: Detects ${{ github.head_ref }} injection', () => {
    const tmp = makeTempWorkflow(`
name: Branch Build
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo \${{ github.head_ref }}
`);
    try {
      const threats = scanGitHubActions(tmp);
      const t = threats.find(t => t.type === 'workflow_injection');
      assert(t, 'Should detect workflow injection via github.head_ref');
    } finally { cleanupTemp(tmp); }
  });

  // --- shai_hulud_backdoor detection ---

  test('GHA: Detects Shai-Hulud backdoor in discussion.yaml', () => {
    const tmp = makeTempWorkflow(`
name: Discussion Bot
on: discussion
jobs:
  reply:
    runs-on: ubuntu-latest
    steps:
      - run: echo \${{ github.event.discussion.body }}
`, 'discussion.yaml');
    try {
      const threats = scanGitHubActions(tmp);
      const t = threats.find(t => t.type === 'shai_hulud_backdoor');
      assert(t, 'Should detect Shai-Hulud backdoor in discussion.yaml');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  test('GHA: Detects Shai-Hulud backdoor in discussion.yml', () => {
    const tmp = makeTempWorkflow(`
name: Discussion Bot
on: discussion
jobs:
  reply:
    runs-on: ubuntu-latest
    steps:
      - run: echo \${{ github.event.discussion.body }}
`, 'discussion.yml');
    try {
      const threats = scanGitHubActions(tmp);
      const t = threats.find(t => t.type === 'shai_hulud_backdoor');
      assert(t, 'Should detect Shai-Hulud backdoor in discussion.yml');
    } finally { cleanupTemp(tmp); }
  });

  // --- Benign workflows (no threats) ---

  test('GHA: No threats on safe workflow', () => {
    const tmp = makeTempWorkflow(`
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
`);
    try {
      const threats = scanGitHubActions(tmp);
      assert(threats.length === 0, 'Safe workflow should produce 0 threats, got ' + threats.length);
    } finally { cleanupTemp(tmp); }
  });

  // --- Edge cases ---

  test('GHA: No threats when .github dir does not exist', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-gha-'));
    try {
      const threats = scanGitHubActions(tmp);
      assert(threats.length === 0, 'No .github dir should produce 0 threats');
    } finally { cleanupTemp(tmp); }
  });

  test('GHA: Ignores injection patterns inside YAML comments', () => {
    const tmp = makeTempWorkflow(`
name: Commented
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # - run: echo \${{ github.event.comment.body }}
      - run: echo "hello"
`);
    try {
      const threats = scanGitHubActions(tmp);
      const t = threats.find(t => t.type === 'workflow_injection');
      assert(!t, 'Commented-out injection should NOT trigger workflow_injection');
    } finally { cleanupTemp(tmp); }
  });

  test('GHA: Ignores non-YAML files in workflows dir', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-gha-'));
    const workflowDir = path.join(tmp, '.github', 'workflows');
    fs.mkdirSync(workflowDir, { recursive: true });
    fs.writeFileSync(path.join(workflowDir, 'readme.md'), '${{ github.event.comment.body }}');
    try {
      const threats = scanGitHubActions(tmp);
      assert(threats.length === 0, 'Non-YAML files should be ignored');
    } finally { cleanupTemp(tmp); }
  });

  test('GHA: Scans .github/actions/ directory too', () => {
    const tmp = makeTempAction(`
name: My Action
runs:
  using: composite
  steps:
    - run: echo \${{ github.event.issue.body }}
`);
    try {
      const threats = scanGitHubActions(tmp);
      const t = threats.find(t => t.type === 'workflow_injection');
      assert(t, 'Should detect injection in .github/actions/ directory');
    } finally { cleanupTemp(tmp); }
  });

  test('GHA: discussion.yaml without injection body is not flagged as backdoor', () => {
    const tmp = makeTempWorkflow(`
name: Discussion Label
on: discussion
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: echo "discussion created"
`, 'discussion.yaml');
    try {
      const threats = scanGitHubActions(tmp);
      const t = threats.find(t => t.type === 'shai_hulud_backdoor');
      assert(!t, 'discussion.yaml without body reference should NOT trigger shai_hulud_backdoor');
    } finally { cleanupTemp(tmp); }
  });

  test('GHA: File path uses forward slashes', () => {
    const tmp = makeTempWorkflow(`
name: Inject
on: issue_comment
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: echo \${{ github.event.comment.body }}
`);
    try {
      const threats = scanGitHubActions(tmp);
      assert(threats.length > 0, 'Should have threats');
      assert(threats[0].file.includes('.github/workflows/'), 'File path should use forward slashes: ' + threats[0].file);
      assert(!threats[0].file.includes('\\'), 'File path should not contain backslashes: ' + threats[0].file);
    } finally { cleanupTemp(tmp); }
  });

  // --- GHA-004: workflow_secrets_dump ---

  test('GHA: Detects toJSON(secrets) secrets dump', () => {
    const tmp = makeTempWorkflow(`
name: Run Copilot
run-name: Run Copilot
on:
  push:
jobs:
  format:
    runs-on: ubuntu-latest
    env:
      VARIABLE_STORE: \${{ toJSON(secrets) }}
    steps:
      - uses: actions/checkout@v4
      - name: Copilot Setup
        run: echo "$VARIABLE_STORE" > format-results.txt
      - uses: actions/upload-artifact@v4
        with:
          name: format-results
          path: format-results.txt
`);
    try {
      const threats = scanGitHubActions(tmp);
      const t = threats.find(t => t.type === 'workflow_secrets_dump');
      assert(t, 'Should detect toJSON(secrets) secrets dump');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  test('GHA: Detects toJSON( secrets ) with spaces', () => {
    const tmp = makeTempWorkflow(`
name: Exfil
on: push
jobs:
  dump:
    runs-on: ubuntu-latest
    env:
      ALL_SECRETS: \${{ toJSON( secrets ) }}
    steps:
      - run: echo "$ALL_SECRETS"
`);
    try {
      const threats = scanGitHubActions(tmp);
      const t = threats.find(t => t.type === 'workflow_secrets_dump');
      assert(t, 'Should detect toJSON( secrets ) with spaces');
    } finally { cleanupTemp(tmp); }
  });

  test('GHA: No false positive on secrets.GITHUB_TOKEN (normal usage)', () => {
    const tmp = makeTempWorkflow(`
name: CI
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "deploying"
        env:
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
`);
    try {
      const threats = scanGitHubActions(tmp);
      const t = threats.find(t => t.type === 'workflow_secrets_dump');
      assert(!t, 'Should NOT flag normal secrets.GITHUB_TOKEN usage');
    } finally { cleanupTemp(tmp); }
  });

  test('GHA: No false positive on toJSON(secrets) in YAML comment', () => {
    const tmp = makeTempWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # WARNING: never use toJSON(secrets) in production
      - run: echo "safe"
`);
    try {
      const threats = scanGitHubActions(tmp);
      const t = threats.find(t => t.type === 'workflow_secrets_dump');
      assert(!t, 'Should NOT flag toJSON(secrets) inside a YAML comment');
    } finally { cleanupTemp(tmp); }
  });

  // --- GHA-005 / GHA-006: unpinned third-party action ---

  test('GHA-005: third-party action pinned to a mutable tag → unpinned_action (LOW)', () => {
    const tmp = makeTempWorkflow(`
jobs:
  build:
    steps:
      - uses: tj-actions/changed-files@v45
`);
    try {
      const threats = scanGitHubActions(tmp);
      const t = threats.find(t => t.type === 'unpinned_action');
      assert(t, 'Should flag unpinned third-party action');
      assert(t.severity === 'LOW', `Should be LOW informational, got ${t && t.severity}`);
      assert(!threats.some(t => t.type === 'unpinned_action_in_risky_workflow'),
        'No compound without a risky trigger');
    } finally { cleanupTemp(tmp); }
  });

  test('GHA-006: unpinned third-party + pwn-request → CRITICAL compound', () => {
    const tmp = makeTempWorkflow(`
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - uses: tj-actions/changed-files@v45
`);
    try {
      const threats = scanGitHubActions(tmp);
      const c = threats.find(t => t.type === 'unpinned_action_in_risky_workflow');
      assert(c, 'Should fire the unpinned-in-risky-workflow compound');
      assert(c.severity === 'CRITICAL', `Compound should be CRITICAL, got ${c && c.severity}`);
      assert(c.compound === true, 'Compound flag must be set (bypasses MT-1, counts as confirmed malice)');
    } finally { cleanupTemp(tmp); }
  });

  test('GHA-005 (FP guard): SHA-pinned third-party action → no finding', () => {
    const tmp = makeTempWorkflow(`
jobs:
  build:
    steps:
      - uses: tj-actions/changed-files@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
`);
    try {
      const threats = scanGitHubActions(tmp);
      assert(!threats.some(t => t.type === 'unpinned_action'),
        'A 40-hex SHA pin is correct — must not be flagged');
    } finally { cleanupTemp(tmp); }
  });

  test('GHA-005 (FP guard): first-party actions/checkout@v4 → no noise', () => {
    const tmp = makeTempWorkflow(`
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/analyze@v3
`);
    try {
      const threats = scanGitHubActions(tmp);
      assert(!threats.some(t => t.type === 'unpinned_action'),
        'Official actions/* and github/* orgs are trusted with tag pins — no noise');
    } finally { cleanupTemp(tmp); }
  });

  test('GHA-005 (FP guard): local ./ action → no finding', () => {
    const tmp = makeTempWorkflow(`
jobs:
  build:
    steps:
      - uses: ./.github/actions/my-local-action
`);
    try {
      const threats = scanGitHubActions(tmp);
      assert(!threats.some(t => t.type === 'unpinned_action'),
        'Local first-party actions have no upstream tag to retag');
    } finally { cleanupTemp(tmp); }
  });

  // --- Scoring context: repository checkout vs downloaded package ---------------
  // A workflow file is never require()d, so the import-graph "unreachable" downgrade sent
  // every workflow finding to LOW (pwn request CRITICAL -> score 1, Shai-Hulud backdoor ->
  // score 2). In a repository checkout the workflows run; in a downloaded package they are
  // inert for the consumer, except the Shai-Hulud backdoor, an infection trace.

  const WF_PWN = 'on:\n  pull_request_target:\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: npm install\n';
  const WF_INJECTION = 'on:\n  issues:\n    types: [opened]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ github.event.issue.title }}"\n';
  const WF_SHAI = 'name: Discussion Create\non:\n  discussion:\njobs:\n  p:\n    runs-on: self-hosted\n    steps:\n      - run: echo ${{ github.event.discussion.body }}\n';
  const WF_TAG = 'on: [push]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: some-org/some-action@v1\n      - run: npm test\n';

  async function scanWorkflow(yaml, fileName, { repository = false, monitorMode = false } = {}) {
    const tmp = makeTempWorkflow(yaml, fileName);
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'gha-ctx', version: '1.0.0', main: 'index.js' }));
    fs.writeFileSync(path.join(tmp, 'index.js'), 'module.exports = 1;\n');
    if (repository) require('child_process').execFileSync('git', ['init', '-q'], { cwd: tmp, stdio: 'pipe' });
    try {
      const r = await runScanDirect(tmp, { monitorMode });
      return { score: r.summary.riskScore, sev: type => (r.threats.find(t => t.type === type) || {}).severity };
    } finally { cleanupTemp(tmp); }
  }

  await asyncTest('GHA-CTX: pwn request in a repository checkout keeps CRITICAL', async () => {
    const r = await scanWorkflow(WF_PWN, 'pwn.yml', { repository: true });
    assert(r.sev('workflow_pwn_request') === 'CRITICAL', 'severity ' + r.sev('workflow_pwn_request'));
    assert(r.score >= 25, 'score ' + r.score);
  });

  await asyncTest('GHA-CTX: workflow injection in a repository checkout keeps HIGH', async () => {
    const r = await scanWorkflow(WF_INJECTION, 'triage.yml', { repository: true });
    assert(r.sev('workflow_injection') === 'HIGH', 'severity ' + r.sev('workflow_injection'));
  });

  await asyncTest('GHA-CTX: workflow findings of a downloaded package stay LOW (negative)', async () => {
    const pwn = await scanWorkflow(WF_PWN, 'pwn.yml');
    const inj = await scanWorkflow(WF_INJECTION, 'triage.yml');
    assert(pwn.sev('workflow_pwn_request') === 'LOW' && pwn.score <= 3, `pwn ${pwn.sev('workflow_pwn_request')} ${pwn.score}`);
    assert(inj.sev('workflow_injection') === 'LOW', 'injection ' + inj.sev('workflow_injection'));
  });

  await asyncTest('GHA-CTX: the monitor is always package context, even with a .git (negative)', async () => {
    const r = await scanWorkflow(WF_PWN, 'pwn.yml', { repository: true, monitorMode: true });
    assert(r.sev('workflow_pwn_request') === 'LOW', 'severity ' + r.sev('workflow_pwn_request'));
  });

  await asyncTest('GHA-CTX: the Shai-Hulud discussion.yaml backdoor is CRITICAL in a package and in a repository', async () => {
    for (const repository of [false, true]) {
      const r = await scanWorkflow(WF_SHAI, 'discussion.yaml', { repository });
      assert(r.sev('shai_hulud_backdoor') === 'CRITICAL', `repository=${repository}: ${r.sev('shai_hulud_backdoor')}`);
      assert(r.score >= 25, `repository=${repository}: score ${r.score}`);
    }
  });

  await asyncTest('GHA-CTX: a mutable action tag stays a hygiene finding in a repository (negative)', async () => {
    const r = await scanWorkflow(WF_TAG, 'ci.yml', { repository: true });
    const s = r.sev('unpinned_action');
    assert(s === undefined || s === 'LOW', 'unpinned_action must not be raised, got ' + s);
    assert(r.score <= 3, 'score ' + r.score);
  });

  // --- GHA-007: attacker-controlled context handed to an action input ----------------

  const inputFindings = (yamlText, maker = makeTempWorkflow) => {
    const tmp = maker(yamlText);
    try { return scanGitHubActions(tmp); } finally { cleanupTemp(tmp); }
  };
  const WF_INPUT = 'on: issue_comment\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n' +
    '      - uses: some-org/comment-action@v1\n        with:\n          body: ${{ github.event.comment.body }}\n';

  test('GHA-007: context passed to a third-party action input is MEDIUM, not an injection, no compound', () => {
    const t = inputFindings(WF_INPUT);
    const f = t.filter(x => x.type === 'workflow_context_to_action_input');
    assert(f.length === 1 && f[0].severity === 'MEDIUM', 'one MEDIUM finding expected: ' + JSON.stringify(t.map(x => x.type)));
    assert(/comment-action/.test(f[0].message) && /"body"/.test(f[0].message), 'message names the action and the input: ' + f[0].message);
    assert(!t.some(x => x.type === 'workflow_injection'), 'must not be reported as an injection');
    assert(!t.some(x => x.type === 'unpinned_action_in_risky_workflow'), 'must not feed the GHA-006 compound (unpinned @v1 here)');
  });

  test('GHA-007: a local action input is reported too', () => {
    const t = inputFindings('on: issues\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n' +
      '      - uses: ./.github/actions/triage\n        with:\n          title: ${{ github.event.issue.title }}\n');
    assert(t.some(x => x.type === 'workflow_context_to_action_input'), 'local action input expected');
  });

  test('GHA-007: first-party actions and non-attacker contexts are not reported (negative)', () => {
    const t = inputFindings('on: issues\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n' +
      '      - uses: actions/upload-artifact@v4\n        with:\n          name: ${{ github.event.issue.title }}\n' +
      '      - uses: some-org/x@v1\n        with:\n          number: ${{ github.event.issue.number }}\n');
    assert(!t.some(x => x.type === 'workflow_context_to_action_input'), 'unexpected: ' + JSON.stringify(t.map(x => x.type)));
  });

  await asyncTest('GHA-007: keeps MEDIUM in a repository checkout, LOW in a downloaded package', async () => {
    const repo = await scanWorkflow(WF_INPUT, 'bot.yml', { repository: true });
    assert(repo.sev('workflow_context_to_action_input') === 'MEDIUM', 'repository: ' + repo.sev('workflow_context_to_action_input'));
    const pkg = await scanWorkflow(WF_INPUT, 'bot.yml');
    assert(pkg.sev('workflow_context_to_action_input') === 'LOW', 'package: ' + pkg.sev('workflow_context_to_action_input'));
  });
}

module.exports = { runGitHubActionsTests };
