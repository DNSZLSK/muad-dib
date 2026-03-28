'use strict';

const helpText = `
  MUAD'DIB - npm & PyPI Supply Chain Threat Hunter

  Usage:
    muaddib                          Interactive mode
    muaddib scan [path] [options]    Scan a project
    muaddib diff <ref> [path]        Compare threats with a previous version
    muaddib install <pkg> [options]  Safe install (scan before install)
    muaddib watch [path]             Watch in real-time
    muaddib sandbox <pkg> [options]  Analyze in isolated Docker container
    muaddib sandbox-report <pkg>     Sandbox + detailed network report
    muaddib evaluate [options]       Run TPR/FPR/ADR evaluation suite
    muaddib monitor [options]        Start real-time npm/PyPI monitor
    muaddib daemon [options]         Start daemon
    muaddib init-hooks [options]     Setup git pre-commit hooks
    muaddib remove-hooks [path]      Remove MUAD'DIB git hooks
    muaddib update                   Update IOCs
    muaddib scrape                   Scrape new IOCs
    muaddib feed [options]           Threat feed (JSON)
    muaddib serve [options]          Threat feed HTTP server
    muaddib detections [options]     View monitor detections
    muaddib stats [options]          View scan statistics
    muaddib replay [options]         Replay ground-truth attacks
    muaddib version                  Show version

  Scan Options:
    --json              JSON output
    --html [file]       HTML report (default: muaddib-report.html)
    --sarif [file]      SARIF report (default: muaddib-results.sarif)
    --explain           Detailed explanations with MITRE references
    --breakdown         Show score breakdown by threat
    --fail-on [level]   Exit code threshold (critical|high|medium|low, default: high)
    --webhook [url]     Discord/Slack webhook (HTTPS only)
    --paranoid          Ultra-strict detection mode
    --exclude [dir]     Exclude directory from scan (repeatable)
    --config [file]     Custom config file (.muaddibrc.json format)
    --entropy-threshold [n]  Custom entropy threshold (0-8, default: 5.5)
    --no-deobfuscate    Disable deobfuscation pre-processing
    --no-module-graph   Disable cross-file dataflow analysis
    --no-reachability   Disable entry-point reachability analysis
    --auto-sandbox      Auto-trigger sandbox when static scan score >= 20 (requires Docker)

  Temporal Options (scan):
    --temporal          Detect sudden lifecycle script changes
    --temporal-ast      Detect sudden dangerous API additions via AST diff
    --temporal-publish  Detect publish frequency anomalies
    --temporal-maintainer  Detect maintainer changes
    --temporal-full     All temporal analyses combined

  Diff Examples:
    muaddib diff HEAD~1              Compare with previous commit
    muaddib diff v1.2.0              Compare with tag
    muaddib diff main                Compare with branch
    muaddib diff abc1234 ./myproject Compare specific commit

  Install Options:
    --save-dev, -D      Install as dev dependency
    -g, --global        Install globally
    --force             Force install despite threats

  Sandbox Options:
    --local             Analyze a local path instead of npm package
    --strict            Block non-essential network access
    --no-canary         Disable honey token injection

  Init-hooks Options:
    --type [auto|husky|pre-commit|git]  Hook system (default: auto)
    --mode [scan|diff]                  scan=all threats, diff=new only

  Evaluate Options:
    --json              JSON output
    --benign-limit [n]  Limit benign packages to scan
    --refresh-benign    Re-download benign packages

  Feed/Serve Options:
    --limit [n]         Limit feed entries (default: 50)
    --severity [level]  Filter by severity (CRITICAL|HIGH|MEDIUM|LOW)
    --since [date]      Filter detections after date (ISO 8601)
    --port [n]          HTTP server port (default: 3000)

  Monitor Options:
    --verbose           Show detailed output
    --temporal --test <pkg>      Test temporal analysis on a single package
    --temporal-ast --test <pkg>  Test AST diff on a single package

  Detections Options:
    --json              JSON output
    --stats             Show aggregated detection statistics

  Stats Options:
    --json              JSON output
    --daily             Show daily breakdown (last 7 days)

  Replay Options:
    --verbose           Show detailed findings per attack
    --json              Machine-readable JSON output
    GT-NNN              Replay single attack by ID
`;

// Per-command help texts for subcommand --help
const commandHelp = {
  scan: `
  Usage: muaddib scan [path] [options]

  Scan a project for supply-chain threats.

  Arguments:
    path                Target directory to scan (default: .)

  Options:
    --json              JSON output
    --html [file]       HTML report (default: muaddib-report.html)
    --sarif [file]      SARIF report (default: muaddib-results.sarif)
    --explain           Detailed explanations with MITRE references
    --breakdown         Show score breakdown by threat
    --fail-on [level]   Exit code threshold (critical|high|medium|low, default: high)
    --webhook [url]     Discord/Slack webhook (HTTPS only)
    --paranoid          Ultra-strict detection mode
    --exclude [dir]     Exclude directory from scan (repeatable)
    --config [file]     Custom config file (.muaddibrc.json format)
    --entropy-threshold [n]  Custom entropy threshold (0-8, default: 5.5)
    --no-deobfuscate    Disable deobfuscation pre-processing
    --no-module-graph   Disable cross-file dataflow analysis
    --no-reachability   Disable entry-point reachability analysis
    --auto-sandbox      Auto-trigger sandbox when static scan score >= 20 (requires Docker)
    --temporal          Detect sudden lifecycle script changes
    --temporal-ast      Detect sudden dangerous API additions
    --temporal-publish  Detect publish frequency anomalies
    --temporal-maintainer  Detect maintainer changes
    --temporal-full     All temporal analyses combined

  Examples:
    muaddib scan .
    muaddib scan ./my-project --explain --paranoid
    muaddib scan . --json > results.json
    muaddib scan . --html report.html --explain
`,
  diff: `
  Usage: muaddib diff <ref> [path] [options]

  Compare threats between two versions of a project.
  Without <ref>, shows available tags and recent commits.

  Arguments:
    ref                 Commit hash, tag, or branch to compare with
    path                Target directory (default: .)

  Options:
    --json              JSON output
    --explain           Detailed explanations
    --fail-on [level]   Exit code threshold (critical|high|medium|low)
    --paranoid          Ultra-strict detection mode

  Examples:
    muaddib diff HEAD~1
    muaddib diff v1.2.0
    muaddib diff main ./myproject
`,
  install: `
  Usage: muaddib install <package> [<package>...] [options]

  Scan packages for threats before installing them.

  Options:
    --save-dev, -D      Install as dev dependency
    -g, --global        Install globally
    --force             Force install despite detected threats

  Examples:
    muaddib install lodash
    muaddib install express morgan --save-dev
    muaddib install -g typescript
`,
  sandbox: `
  Usage: muaddib sandbox <package-name|path> [options]

  Run dynamic analysis in an isolated Docker container.
  Requires Docker to be installed and running.

  Options:
    --local             Analyze a local path instead of npm package
    --strict            Block non-essential network access
    --no-canary         Disable honey token injection

  Examples:
    muaddib sandbox suspicious-pkg
    muaddib sandbox ./local-pkg --local --strict
`,
  'sandbox-report': `
  Usage: muaddib sandbox-report <package-name|path> [options]

  Run sandbox analysis with detailed network traffic report.
  Same options as 'muaddib sandbox'.
`,
  evaluate: `
  Usage: muaddib evaluate [options]

  Run the full TPR/FPR/ADR evaluation suite against ground truth,
  benign packages, and adversarial samples.

  Options:
    --json              JSON output
    --benign-limit [n]  Limit benign packages to scan
    --refresh-benign    Re-download benign packages

  Examples:
    muaddib evaluate
    muaddib evaluate --json > eval-results.json
`,
  monitor: `
  Usage: muaddib monitor [options]

  Start real-time monitoring of npm/PyPI registries for
  newly published malicious packages.

  Options:
    --verbose                        Show detailed output
    --temporal --test <pkg>          Test temporal analysis on a single package
    --temporal-ast --test <pkg>      Test AST diff on a single package

  Examples:
    muaddib monitor
    muaddib monitor --verbose
    muaddib monitor --temporal --test lodash
`,
  feed: `
  Usage: muaddib feed [options]

  Output the threat detection feed as JSON.

  Options:
    --limit [n]         Limit entries (default: 50)
    --severity [level]  Filter by severity (CRITICAL|HIGH|MEDIUM|LOW)
    --since [date]      Filter after date (ISO 8601)

  Examples:
    muaddib feed
    muaddib feed --severity CRITICAL --limit 10
`,
  serve: `
  Usage: muaddib serve [options]

  Start an HTTP server serving the threat feed.

  Options:
    --port [n]          Server port (default: 3000)

  Examples:
    muaddib serve
    muaddib serve --port 8080
`,
  detections: `
  Usage: muaddib detections [options]

  View detections recorded by the monitor.

  Options:
    --json              Full JSON output
    --stats             Show aggregated detection statistics

  Examples:
    muaddib detections
    muaddib detections --stats
    muaddib detections --json > detections.json
`,
  stats: `
  Usage: muaddib stats [options]

  View scan statistics from the monitor.

  Options:
    --json              JSON output
    --daily             Show daily breakdown (last 7 days)

  Examples:
    muaddib stats
    muaddib stats --daily
`,
  replay: `
  Usage: muaddib replay [options] [GT-NNN]

  Replay ground-truth attack samples to verify detection.

  Options:
    --verbose, -v       Show detailed findings per attack
    --json              Machine-readable JSON output
    GT-NNN              Replay a single attack by ID

  Examples:
    muaddib replay
    muaddib replay --verbose
    muaddib replay GT-001
`,
  'init-hooks': `
  Usage: muaddib init-hooks [options]

  Setup git pre-commit hooks for automatic scanning.

  Options:
    --type [auto|husky|pre-commit|git]  Hook system (default: auto)
    --mode [scan|diff]                  scan=all threats, diff=new only

  Examples:
    muaddib init-hooks
    muaddib init-hooks --type husky --mode diff
`,
  'remove-hooks': `
  Usage: muaddib remove-hooks [path]

  Remove MUAD'DIB git hooks from a project.
`,
  watch: `
  Usage: muaddib watch [path]

  Watch a project directory and re-scan on file changes.

  Examples:
    muaddib watch
    muaddib watch ./my-project
`,
  daemon: `
  Usage: muaddib daemon [options]

  Start the MUAD'DIB daemon for background monitoring.

  Options:
    --webhook [url]     Discord/Slack webhook URL

  Examples:
    muaddib daemon
    muaddib daemon --webhook https://discord.com/api/webhooks/...
`,
  report: `
  Usage: muaddib report --now | --status

  Send or check status of daily monitor reports.

  Options:
    --now               Send report immediately
    --status            Show report status
`,
};

// Show per-command help or global help
function showHelp(cmd) {
  if (cmd && commandHelp[cmd]) {
    console.log(commandHelp[cmd]);
  } else {
    console.log(helpText);
  }
  process.exit(0);
}

module.exports = { helpText, commandHelp, showHelp };
