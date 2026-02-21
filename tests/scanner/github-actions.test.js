const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, assert, cleanupTemp } = require('../test-utils');

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
}

module.exports = { runGitHubActionsTests };
