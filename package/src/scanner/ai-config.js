/**
 * AI Config Injection Scanner
 *
 * Detects prompt injection attacks hidden in AI agent configuration files:
 * .cursorrules, CLAUDE.md, AGENT.md, .github/copilot-instructions.md,
 * copilot-setup-steps.yml, .cursorignore, .windsurfrules, etc.
 *
 * These files are designed to be read by AI coding assistants and may contain
 * hidden instructions to execute shell commands, exfiltrate secrets, or
 * download and run remote payloads.
 *
 * References:
 * - ToxicSkills (Snyk, Feb 2026)
 * - NVIDIA AI agent security guidance
 * - arxiv 2601.17548 (prompt injection in AI agents)
 * - Clinejection (Snyk, Feb 2026)
 */

const fs = require('fs');
const path = require('path');

// AI agent config files to scan (relative to project root)
const AI_CONFIG_FILES = [
  '.cursorrules',
  '.cursorignore',
  '.windsurfrules',
  'CLAUDE.md',
  'AGENT.md',
  '.github/copilot-instructions.md',
  'copilot-setup-steps.yml',
  '.github/copilot-setup-steps.yml'
];

// Dangerous shell command patterns in AI config files
const SHELL_COMMAND_PATTERNS = [
  // Download and execute
  { regex: /curl\s+[^\n]*\|\s*(sh|bash|zsh)\b/i, label: 'curl pipe to shell', critical: true },
  { regex: /wget\s+[^\n]*\|\s*(sh|bash|zsh)\b/i, label: 'wget pipe to shell', critical: true },
  { regex: /curl\s+-[sS]*L?\s+https?:\/\/[^\s"']+\s*\|\s*(sh|bash)/i, label: 'curl download and execute', critical: true },
  { regex: /wget\s+-[qQ]*O?-?\s+https?:\/\/[^\s"']+\s*\|\s*(sh|bash)/i, label: 'wget download and execute', critical: true },

  // Direct shell execution
  { regex: /\beval\s*\(/i, label: 'eval() call', critical: false },
  { regex: /\bexec\s*\(/i, label: 'exec() call', critical: false },
  { regex: /\bsource\s+\.env\b/i, label: 'source .env', critical: false },
  { regex: /\bsh\s+-c\s+["']/i, label: 'sh -c execution', critical: false },
  { regex: /\bbash\s+-c\s+["']/i, label: 'bash -c execution', critical: false },
  { regex: /\bnode\s+-e\s+["']/i, label: 'node -e inline execution', critical: false },
  { regex: /\bpython[3]?\s+-c\s+["']/i, label: 'python -c inline execution', critical: false }
];

// Exfiltration patterns — sending data to external endpoints
const EXFIL_PATTERNS = [
  { regex: /curl\s+[^\n]*-X\s*POST\s+[^\n]*https?:\/\/(?!api\.github\.com|registry\.npmjs\.org)[^\s"']+/i, label: 'curl POST to external endpoint' },
  { regex: /curl\s+[^\n]*-d\s+[^\n]*https?:\/\/(?!api\.github\.com|registry\.npmjs\.org)[^\s"']+/i, label: 'curl data upload to external endpoint' },
  { regex: /curl\s+[^\n]*https?:\/\/(?!api\.github\.com|registry\.npmjs\.org)[^\s"']+[^\n]*-d\s/i, label: 'curl data upload to external endpoint' },
  { regex: /\|\s*curl\s+[^\n]*https?:\/\/(?!api\.github\.com|registry\.npmjs\.org)/i, label: 'pipe output to curl' },
  { regex: /\|\s*base64\s*\|\s*curl/i, label: 'base64 encode and send via curl' }
];

// Credential access patterns — reading sensitive files/vars
const CREDENTIAL_ACCESS_PATTERNS = [
  { regex: /cat\s+~?\/?\.ssh\/id_/i, label: 'read SSH private key' },
  { regex: /cat\s+~?\/?\.npmrc/i, label: 'read .npmrc tokens' },
  { regex: /cat\s+~?\/?\.aws\/credentials/i, label: 'read AWS credentials' },
  { regex: /cat\s+~?\/?\.env\b/i, label: 'read .env file' },
  { regex: /cat\s+~?\/?\.gnupg\//i, label: 'read GPG keys' },
  { regex: /\$GITHUB_TOKEN|\$GH_TOKEN|\$NPM_TOKEN|\$AWS_SECRET_ACCESS_KEY|\$DISCORD_TOKEN/i, label: 'reference to secret env var' },
  { regex: /grep\s+[^\n]*(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)[^\n]*/i, label: 'grep for secrets' },
  { regex: /env\s*\|\s*grep\s+[^\n]*(TOKEN|KEY|SECRET|PASSWORD)/i, label: 'env grep for secrets' }
];

// Instruction patterns — AI prompt injection directives
const INJECTION_INSTRUCTION_PATTERNS = [
  { regex: /before\s+(reviewing|running|any|code|generating)[^\n]*(run|execute|source):/i, label: 'instruction to execute before review' },
  { regex: /always\s+run\s+[^\n]*(before|first|initially)/i, label: 'instruction to always run command' },
  { regex: /send\s+(contents?|data|output|results?)\s+(to|via)\s+https?:\/\//i, label: 'instruction to send data to URL' },
  { regex: /upload\s+[^\n]*(to|via)\s+https?:\/\//i, label: 'instruction to upload to URL' },
  { regex: /do\s+not\s+(display|show|output|mention|tell)/i, label: 'instruction to hide activity' }
];

/**
 * Scan AI config files for prompt injection
 */
function scanAIConfig(targetPath) {
  const threats = [];

  for (const configFile of AI_CONFIG_FILES) {
    const filePath = path.join(targetPath, configFile);

    if (!fs.existsSync(filePath)) continue;

    let content;
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > 1024 * 1024) continue; // Skip files > 1MB
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }

    const relPath = configFile;
    const fileThreats = analyzeAIConfigFile(content, relPath);
    threats.push(...fileThreats);
  }

  return threats;
}

/**
 * Analyze a single AI config file for prompt injection patterns
 */
function analyzeAIConfigFile(content, relPath) {
  const threats = [];
  let hasShellCommand = false;
  let hasExfiltration = false;
  let hasCredentialAccess = false;

  // Check shell command patterns
  for (const pattern of SHELL_COMMAND_PATTERNS) {
    if (pattern.regex.test(content)) {
      hasShellCommand = true;
      threats.push({
        type: pattern.critical ? 'ai_config_injection_critical' : 'ai_config_injection',
        severity: pattern.critical ? 'CRITICAL' : 'HIGH',
        message: `AI config prompt injection: ${pattern.label} in ${relPath}`,
        file: relPath
      });
    }
  }

  // Check exfiltration patterns
  for (const pattern of EXFIL_PATTERNS) {
    if (pattern.regex.test(content)) {
      hasExfiltration = true;
      threats.push({
        type: 'ai_config_injection_critical',
        severity: 'CRITICAL',
        message: `AI config exfiltration: ${pattern.label} in ${relPath}`,
        file: relPath
      });
    }
  }

  // Check credential access patterns
  for (const pattern of CREDENTIAL_ACCESS_PATTERNS) {
    if (pattern.regex.test(content)) {
      hasCredentialAccess = true;
      threats.push({
        type: 'ai_config_injection',
        severity: 'HIGH',
        message: `AI config credential access: ${pattern.label} in ${relPath}`,
        file: relPath
      });
    }
  }

  // Check injection instruction patterns
  for (const pattern of INJECTION_INSTRUCTION_PATTERNS) {
    if (pattern.regex.test(content)) {
      threats.push({
        type: 'ai_config_injection',
        severity: 'HIGH',
        message: `AI config prompt injection: ${pattern.label} in ${relPath}`,
        file: relPath
      });
    }
  }

  // Compound detection: shell + exfil or credential access → escalate
  if (hasShellCommand && (hasExfiltration || hasCredentialAccess)) {
    threats.push({
      type: 'ai_config_injection_critical',
      severity: 'CRITICAL',
      message: `AI config compound attack: shell commands + ${hasExfiltration ? 'exfiltration' : 'credential access'} in ${relPath} — ToxicSkills/Clinejection pattern.`,
      file: relPath
    });
  }

  return threats;
}

module.exports = { scanAIConfig };
