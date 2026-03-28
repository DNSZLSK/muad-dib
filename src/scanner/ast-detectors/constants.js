'use strict';

// ============================================
// AST DETECTION CONSTANTS
// ============================================

const DANGEROUS_CALLS = [
  'eval',
  'Function'
];

const SENSITIVE_STRINGS = [
  '.npmrc',
  '.ssh',
  'Shai-Hulud',
  'The Second Coming',
  'Goldox-T3chs',
  '/etc/passwd',
  '/etc/shadow'
];

// Env vars that are safe and should NOT be flagged (common config/runtime vars)
const SAFE_ENV_VARS = [
  'NODE_ENV', 'PORT', 'HOST', 'HOSTNAME', 'PWD', 'HOME', 'PATH',
  'LANG', 'TERM', 'CI', 'DEBUG', 'VERBOSE', 'LOG_LEVEL',
  'SHELL', 'USER', 'LOGNAME', 'EDITOR', 'TZ',
  'NODE_DEBUG', 'NODE_PATH', 'NODE_OPTIONS',
  'DISPLAY', 'COLORTERM', 'FORCE_COLOR', 'NO_COLOR', 'TERM_PROGRAM',
  // CI environment metadata (non-sensitive)
  'GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_REF', 'GITHUB_WORKSPACE',
  'GITHUB_RUN_ID', 'GITHUB_RUN_NUMBER', 'GITHUB_ACTOR', 'GITHUB_EVENT_NAME',
  'GITHUB_WORKFLOW', 'GITHUB_ACTION', 'GITHUB_JOB', 'GITHUB_SERVER_URL',
  'GITLAB_CI', 'TRAVIS', 'CIRCLECI', 'JENKINS_URL',
  // Build tool config
  'NODE_TLS_REJECT_UNAUTHORIZED', 'BABEL_ENV', 'WEBPACK_MODE'
];

// Env var prefixes that are safe (npm metadata, locale settings, framework public vars)
const SAFE_ENV_PREFIXES = [
  'npm_config_', 'npm_lifecycle_', 'npm_package_', 'lc_', 'muaddib_',
  'next_public_', 'vite_', 'react_app_'
];

// Env var keywords to detect sensitive environment access (separate from SENSITIVE_STRINGS)
const ENV_SENSITIVE_KEYWORDS = [
  'TOKEN', 'SECRET', 'KEY', 'PASSWORD', 'CREDENTIAL', 'AUTH'
];

// Non-sensitive qualifiers: when a keyword is preceded by one of these in the env var name,
// it is config metadata, not a real secret (e.g., PUBLIC_KEY, CACHE_KEY, SORT_KEY)
const ENV_NON_SENSITIVE_QUALIFIERS = new Set([
  'PUBLIC', 'CACHE', 'PRIMARY', 'FOREIGN', 'SORT', 'PARTITION', 'INDEX', 'ENCRYPTION'
]);

// AI agent dangerous flags — disable security controls (s1ngularity/Nx, Aug 2025)
const AI_AGENT_DANGEROUS_FLAGS = [
  '--dangerously-skip-permissions',
  '--yolo',
  '--trust-all-tools',
  '--yes-always',
  '--no-permission-check'
];

// AI agent binary names
const AI_AGENT_BINARIES = ['claude', 'gemini', 'q', 'aider', 'copilot', 'cursor'];

// Strings that are NOT suspicious
const SAFE_STRINGS = [
  'api.github.com',
  'registry.npmjs.org',
  'npmjs.com'
];

// Domains where fetch is legitimate (not C2) — used to suppress download_exec_binary compound
const SAFE_FETCH_DOMAINS = [
  'registry.npmjs.org', 'npmjs.com',
  'github.com', 'objects.githubusercontent.com', 'raw.githubusercontent.com',
  'nodejs.org', 'yarnpkg.com',
  'pypi.org', 'files.pythonhosted.org'
];

// Credential-stealing CLI commands (s1ngularity/Nx, Shai-Hulud)
const CREDENTIAL_CLI_COMMANDS = [
  'gh auth token',
  'gcloud auth print-access-token',
  'aws sts get-session-token',
  'az account get-access-token',
  'heroku auth:token',
  'netlify api --data',
  'vercel whoami'
];

// Dangerous shell command patterns for variable tracking
const DANGEROUS_CMD_PATTERNS = [/\bcurl\b/, /\bwget\b/, /\bnc\s+-/, /\/dev\/tcp\//, /\bbash\s+-i/, /\bpowershell\b/, /\bpwsh\b/, /\bnslookup\b/, /\bdig\s+/];

// Native APIs targeted for prototype hooking (chalk Sept 2025, Sygnia)
const HOOKABLE_NATIVES = [
  'fetch', 'XMLHttpRequest', 'Request', 'Response',
  'WebSocket', 'EventSource'
];

// Node.js core module classes targeted for prototype hooking
const NODE_HOOKABLE_MODULES = ['http', 'https', 'net', 'tls', 'stream', 'events', 'dgram'];
const NODE_HOOKABLE_CLASSES = [
  'IncomingMessage', 'ServerResponse', 'ClientRequest',
  'OutgoingMessage', 'Socket', 'Server', 'Agent',
  'EventEmitter'
];

// AI/MCP config paths targeted for config injection (SANDWORM_MODE)
const MCP_CONFIG_PATHS = [
  '.claude/', 'claude_desktop_config',
  '.cursor/', 'mcp.json',
  '.continue/',
  '.vscode/',
  '.windsurf/', '.codeium/'
];

// MCP content indicators in written data
const MCP_CONTENT_PATTERNS = ['mcpServers', '"mcp"', '"server"', '"command"', '"args"'];

// Sensitive AI config files — writes to these are always suspicious regardless of content.
// Split into two tiers:
// - UNIQUE: filenames no legitimate plugin would use (always sensitive)
// - ROOT_ONLY: generic names (settings.json) that are sensitive ONLY when directly
//   at config dir root (e.g. ~/.claude/settings.json), not in subdirectories
//   (e.g. ~/.claude/my-plugin/settings.json which is legitimate plugin config)
const SENSITIVE_AI_CONFIG_FILES_UNIQUE = [
  'claude.md', 'claude_desktop_config.json',
  'mcp.json',
  '.cursorrules', '.windsurfrules',
  'copilot-instructions.md'
];
const SENSITIVE_AI_CONFIG_FILES_ROOT_ONLY = [
  'settings.json', 'settings.local.json'
];

// Git hooks names
const GIT_HOOKS = [
  'pre-commit', 'pre-push', 'post-checkout', 'post-merge',
  'pre-receive', 'post-receive', 'prepare-commit-msg', 'commit-msg',
  'pre-rebase', 'post-rewrite', 'pre-auto-gc'
];

// Suspicious C2/exfiltration domains (HIGH severity)
const SUSPICIOUS_DOMAINS_HIGH = [
  'oastify.com', 'oast.fun', 'oast.me', 'oast.live',
  'burpcollaborator.net', 'webhook.site', 'pipedream.net',
  'requestbin.com', 'hookbin.com', 'canarytokens.com',
  // GlassWorm C2 IPs (mars 2026)
  '217.69.3.218', '217.69.3.152',
  '199.247.10.166', '199.247.13.106',
  '140.82.52.31', '45.32.150.251',
  // TeamPCP/CanisterWorm C2 (mars 2026)
  'icp0.io', 'raw.icp0.io', 'ic0.app',        // ICP canister C2 (decentralized dead-drop)
  'hackmoltrepeat.com',                          // hackerbot-claw payload delivery
  'recv.hackmoltrepeat.com',                     // hackerbot-claw credential receiver
  'scan.aquasecurtiy.org',                       // Trivy exfil C2 (typosquat of aquasecurity)
  'api.telegram.org',                            // Telegram bot exfiltration (crypto typosquats)
  'checkmarx.zone',                              // Checkmarx/LiteLLM exfil C2
  '45.148.10.212', '83.142.209.11'               // TeamPCP C2 IPs
];

// Suspicious tunnel/proxy domains (MEDIUM severity)
const SUSPICIOUS_DOMAINS_MEDIUM = [
  'ngrok.io', 'ngrok-free.app', 'serveo.net', 'localhost.run', 'loca.lt',
  'trycloudflare.com'   // Cloudflare tunnel C2 (CanisterWorm kamikaze.sh stager)
];

// LLM API key environment variable names (3+ = harvesting)
const LLM_API_KEY_VARS = [
  'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GOOGLE_API_KEY',
  'GROQ_API_KEY', 'TOGETHER_API_KEY', 'FIREWORKS_API_KEY',
  'REPLICATE_API_KEY', 'MISTRAL_API_KEY', 'COHERE_API_KEY'
];

// Env harvesting sensitive patterns (for Object.entries/keys/values filtering)
const ENV_HARVEST_PATTERNS = [
  'KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'CREDENTIAL',
  'NPM', 'AWS', 'SSH', 'WEBHOOK'
];

// Paths indicating sandbox/container environment detection (anti-analysis)
const SANDBOX_INDICATORS = [
  '/.dockerenv',
  '/proc/1/cgroup',
  '/proc/self/cgroup'
];

// Blockchain RPC endpoints — potential C2 channel via blockchain (GlassWorm)
const BLOCKCHAIN_RPC_ENDPOINTS = [
  'api.mainnet-beta.solana.com',
  'api.devnet.solana.com',
  'api.testnet.solana.com',
  'mainnet.infura.io',
  'rpc.ankr.com'
];

// Solana/Web3 C2 methods — used for dead drop resolver (GlassWorm)
const SOLANA_C2_METHODS = [
  'getSignaturesForAddress', 'getAccountInfo', 'getTransaction',
  'getConfirmedSignaturesForAddress2', 'getParsedTransaction',
  // Blue Team v8: extended Ethereum/Web3 C2 methods
  'eth_call', 'getCode', 'getLogs'
];

// Blue Team v8: Ethereum/Web3 package names for compound blockchain C2 detection
const ETHEREUM_PACKAGES = ['ethers', 'web3', '@ethersproject/providers', '@ethersproject/contracts'];

// Solana/Web3 package names
const SOLANA_PACKAGES = ['@solana/web3.js', 'solana-web3.js', '@solana/web3'];

// Variation selector constants (GlassWorm decoder signature)
const VARIATION_SELECTOR_CONSTS = [0xFE00, 0xFE0F, 0xE0100, 0xE01EF];

module.exports = {
  DANGEROUS_CALLS,
  SENSITIVE_STRINGS,
  SAFE_ENV_VARS,
  SAFE_ENV_PREFIXES,
  ENV_SENSITIVE_KEYWORDS,
  ENV_NON_SENSITIVE_QUALIFIERS,
  AI_AGENT_DANGEROUS_FLAGS,
  AI_AGENT_BINARIES,
  SAFE_STRINGS,
  SAFE_FETCH_DOMAINS,
  CREDENTIAL_CLI_COMMANDS,
  DANGEROUS_CMD_PATTERNS,
  HOOKABLE_NATIVES,
  NODE_HOOKABLE_MODULES,
  NODE_HOOKABLE_CLASSES,
  MCP_CONFIG_PATHS,
  MCP_CONTENT_PATTERNS,
  SENSITIVE_AI_CONFIG_FILES_UNIQUE,
  SENSITIVE_AI_CONFIG_FILES_ROOT_ONLY,
  GIT_HOOKS,
  SUSPICIOUS_DOMAINS_HIGH,
  SUSPICIOUS_DOMAINS_MEDIUM,
  LLM_API_KEY_VARS,
  ENV_HARVEST_PATTERNS,
  SANDBOX_INDICATORS,
  BLOCKCHAIN_RPC_ENDPOINTS,
  SOLANA_C2_METHODS,
  ETHEREUM_PACKAGES,
  SOLANA_PACKAGES,
  VARIATION_SELECTOR_CONSTS
};
