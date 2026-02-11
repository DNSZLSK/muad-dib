const RULES = {
  // AST detections
  sensitive_string: {
    id: 'MUADDIB-AST-001',
    name: 'Sensitive String Reference',
    severity: 'HIGH',
    confidence: 'medium',
    description: 'Reference a un chemin ou identifiant sensible (.npmrc, .ssh, tokens)',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm',
      'https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack'
    ],
    mitre: 'T1552.001'
  },
  env_access: {
    id: 'MUADDIB-AST-002',
    name: 'Sensitive Environment Variable Access',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Acces a une variable d\'environnement sensible (GITHUB_TOKEN, NPM_TOKEN, AWS_*)',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm',
      'https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions'
    ],
    mitre: 'T1552.001'
  },
  dangerous_call_exec: {
    id: 'MUADDIB-AST-003',
    name: 'Dangerous Function Call',
    severity: 'MEDIUM',
    confidence: 'medium',
    description: 'Appel a une fonction dangereuse (exec, spawn, eval, Function)',
    references: [
      'https://owasp.org/www-community/attacks/Command_Injection'
    ],
    mitre: 'T1059'
  },
  dangerous_call_eval: {
    id: 'MUADDIB-AST-004',
    name: 'Eval Usage',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Utilisation de eval() ou new Function() - execution de code dynamique',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!'
    ],
    mitre: 'T1059.007'
  },

  // Shell detections
  curl_exec: {
    id: 'MUADDIB-SHELL-001',
    name: 'Remote Code Execution via Curl',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Telecharge et execute du code distant via curl | sh',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm'
    ],
    mitre: 'T1105'
  },
  reverse_shell: {
    id: 'MUADDIB-SHELL-002',
    name: 'Reverse Shell',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Tentative de connexion reverse shell',
    references: [
      'https://attack.mitre.org/techniques/T1059/004/'
    ],
    mitre: 'T1059.004'
  },
  home_deletion: {
    id: 'MUADDIB-SHELL-003',
    name: 'Dead Man\'s Switch',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Suppression du repertoire home - dead man\'s switch de Shai-Hulud',
    references: [
      'https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack'
    ],
    mitre: 'T1485'
  },

  // Package detections
  lifecycle_script: {
    id: 'MUADDIB-PKG-001',
    name: 'Suspicious Lifecycle Script',
    severity: 'MEDIUM',
    confidence: 'medium',
    description: 'Script preinstall/postinstall suspect dans package.json',
    references: [
      'https://blog.npmjs.org/post/141577284765/kik-left-pad-and-npm'
    ],
    mitre: 'T1195.002'
  },

  // Obfuscation detections
  obfuscation_detected: {
    id: 'MUADDIB-OBF-001',
    name: 'Code Obfuscation Detected',
    severity: 'HIGH',
    confidence: 'medium',
    description: 'Code fortement obfusque detecte - probablement malveillant',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm'
    ],
    mitre: 'T1027'
  },

  // Dependency detections
  known_malicious_package: {
    id: 'MUADDIB-DEP-001',
    name: 'Known Malicious Package',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Package present dans la base IOC de packages malveillants connus',
    references: [
      'https://socket.dev/npm/issue'
    ],
    mitre: 'T1195.002'
  },
  pypi_malicious_package: {
    id: 'MUADDIB-PYPI-001',
    name: 'Malicious PyPI Package',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Package PyPI present dans la base IOC de packages malveillants connus (source: OSV)',
    references: [
      'https://osv.dev/',
      'https://pypi.org/'
    ],
    mitre: 'T1195.002'
  },
  pypi_typosquat_detected: {
    id: 'MUADDIB-PYPI-002',
    name: 'PyPI Typosquatting Detected',
    severity: 'HIGH',
    confidence: 'medium',
    description: 'Dependance PyPI suspecte de typosquatting d\'un package populaire (Levenshtein)',
    references: [
      'https://pypi.org/',
      'https://blog.phylum.io/typosquatting-pypi'
    ],
    mitre: 'T1195.002'
  },
  suspicious_file: {
    id: 'MUADDIB-DEP-002',
    name: 'Suspicious File in Dependency',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Fichier suspect detecte dans une dependance (setup_bun.js, etc.)',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm'
    ],
    mitre: 'T1195.002'
  },
  shai_hulud_marker: {
    id: 'MUADDIB-DEP-003',
    name: 'Shai-Hulud Marker Detected',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Marqueur Shai-Hulud detecte dans le code',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm',
      'https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack'
    ],
    mitre: 'T1195.002'
  },
  lifecycle_script_dependency: {
    id: 'MUADDIB-DEP-004',
    name: 'Lifecycle Script in Dependency',
    severity: 'MEDIUM',
    confidence: 'low',
    description: 'Une dependance a un script preinstall/postinstall',
    references: [
      'https://docs.npmjs.com/cli/v9/using-npm/scripts#life-cycle-scripts'
    ],
    mitre: 'T1195.002'
  },

  // Hash detections
  known_malicious_hash: {
    id: 'MUADDIB-HASH-001',
    name: 'Known Malicious File Hash',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Hash SHA256 correspond a un fichier malveillant connu',
    references: [
      'https://www.virustotal.com'
    ],
    mitre: 'T1195.002'
  },

  // Dataflow detections
  suspicious_dataflow: {
    id: 'MUADDIB-FLOW-001',
    name: 'Suspicious Data Flow',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Flux de donnees suspect: lecture de credentials puis envoi reseau',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm'
    ],
    mitre: 'T1041'
  },

  typosquat_detected: {
    id: 'MUADDIB-TYPO-001',
    name: 'Typosquatting Detected',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Package avec un nom tres similaire a un package populaire. Possible typosquatting.',
    references: [
      'https://blog.npmjs.org/post/163723642530/crossenv-malware-on-the-npm-registry',
      'https://snyk.io/blog/typosquatting-attacks/'
    ],
    mitre: 'T1195.002'
  },

  // Package.json script patterns
  curl_pipe_sh: {
    id: 'MUADDIB-PKG-002',
    name: 'Curl Pipe to Shell in Script',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Script lifecycle execute curl | sh - telechargement et execution de code distant',
    references: ['https://blog.phylum.io/shai-hulud-npm-worm'],
    mitre: 'T1105'
  },
  wget_pipe_sh: {
    id: 'MUADDIB-PKG-003',
    name: 'Wget Pipe to Shell in Script',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Script lifecycle execute wget | sh - telechargement et execution de code distant',
    references: ['https://blog.phylum.io/shai-hulud-npm-worm'],
    mitre: 'T1105'
  },
  eval_usage: {
    id: 'MUADDIB-PKG-004',
    name: 'Eval in Lifecycle Script',
    severity: 'HIGH',
    confidence: 'medium',
    description: 'Utilisation de eval() dans un script lifecycle - execution de code dynamique',
    references: ['https://owasp.org/www-community/attacks/Command_Injection'],
    mitre: 'T1059.007'
  },
  child_process: {
    id: 'MUADDIB-PKG-005',
    name: 'Child Process in Lifecycle Script',
    severity: 'HIGH',
    confidence: 'medium',
    description: 'Reference a child_process dans un script lifecycle',
    references: ['https://owasp.org/www-community/attacks/Command_Injection'],
    mitre: 'T1059'
  },
  npmrc_access: {
    id: 'MUADDIB-PKG-006',
    name: 'npmrc Access',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Acces au fichier .npmrc detecte - risque de vol de token npm',
    references: ['https://blog.phylum.io/shai-hulud-npm-worm'],
    mitre: 'T1552.001'
  },
  github_token_access: {
    id: 'MUADDIB-PKG-007',
    name: 'GitHub Token Access',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Acces au GITHUB_TOKEN detecte',
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions'],
    mitre: 'T1552.001'
  },
  aws_credential_access: {
    id: 'MUADDIB-PKG-008',
    name: 'AWS Credential Access',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Acces aux credentials AWS detecte',
    references: ['https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html'],
    mitre: 'T1552.001'
  },
  base64_encoding: {
    id: 'MUADDIB-PKG-009',
    name: 'Base64 Encoding in Script',
    severity: 'MEDIUM',
    confidence: 'low',
    description: 'Encodage base64 dans un script lifecycle - souvent utilise pour obfusquer du code malveillant',
    references: ['https://attack.mitre.org/techniques/T1027/'],
    mitre: 'T1027'
  },

  // Shell script patterns
  curl_pipe_shell: {
    id: 'MUADDIB-SHELL-004',
    name: 'Curl Pipe to Shell',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Telechargement et execution via curl | sh dans un script shell',
    references: ['https://blog.phylum.io/shai-hulud-npm-worm'],
    mitre: 'T1105'
  },
  wget_chmod_exec: {
    id: 'MUADDIB-SHELL-005',
    name: 'Wget Download and Execute',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Telechargement et execution de binaire via wget + chmod',
    references: ['https://blog.phylum.io/shai-hulud-npm-worm'],
    mitre: 'T1105'
  },
  netcat_shell: {
    id: 'MUADDIB-SHELL-006',
    name: 'Netcat Shell',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Shell netcat detecte - acces distant non autorise',
    references: ['https://attack.mitre.org/techniques/T1059/004/'],
    mitre: 'T1059.004'
  },
  shred_home: {
    id: 'MUADDIB-SHELL-007',
    name: 'Home Directory Destruction',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Destruction de donnees (shred $HOME) - dead man\'s switch de Shai-Hulud',
    references: ['https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack'],
    mitre: 'T1485'
  },
  curl_exfiltration: {
    id: 'MUADDIB-SHELL-008',
    name: 'Data Exfiltration via Curl',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Exfiltration de donnees via curl POST',
    references: ['https://attack.mitre.org/techniques/T1041/'],
    mitre: 'T1041'
  },
  ssh_access: {
    id: 'MUADDIB-SHELL-009',
    name: 'SSH Key Access',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Acces aux cles SSH detecte',
    references: ['https://attack.mitre.org/techniques/T1552/004/'],
    mitre: 'T1552.004'
  },

  // AST additional patterns
  possible_obfuscation: {
    id: 'MUADDIB-OBF-002',
    name: 'Possible Code Obfuscation',
    severity: 'MEDIUM',
    confidence: 'low',
    description: 'Fichier potentiellement obfusque (parse echoue, code dense)',
    references: ['https://attack.mitre.org/techniques/T1027/'],
    mitre: 'T1027'
  },
  dangerous_call_function: {
    id: 'MUADDIB-AST-005',
    name: 'new Function() Constructor',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Appel new Function() detecte - equivalent a eval()',
    references: ['https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/Function'],
    mitre: 'T1059.007'
  },

  // GitHub Actions patterns
  shai_hulud_backdoor: {
    id: 'MUADDIB-GHA-001',
    name: 'Shai-Hulud GitHub Actions Backdoor',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Backdoor Shai-Hulud dans GitHub Actions via workflow discussion.yaml sur self-hosted runner',
    references: ['https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack'],
    mitre: 'T1195.002'
  },
  workflow_injection: {
    id: 'MUADDIB-GHA-002',
    name: 'GitHub Actions Workflow Injection',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Injection potentielle dans GitHub Actions via input non sanitise sur self-hosted runner',
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions'],
    mitre: 'T1195.002'
  },

  // Sandbox detections
  sandbox_sensitive_file_read: {
    id: 'MUADDIB-SANDBOX-001',
    name: 'Sandbox: Sensitive File Read',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Package reads sensitive credential files during install',
    references: ['https://blog.phylum.io/shai-hulud-npm-worm'],
    mitre: 'T1552.001'
  },
  sandbox_sensitive_file_write: {
    id: 'MUADDIB-SANDBOX-002',
    name: 'Sandbox: Sensitive File Write',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Package writes to sensitive credential files during install',
    references: ['https://blog.phylum.io/shai-hulud-npm-worm'],
    mitre: 'T1565.001'
  },
  sandbox_suspicious_filesystem: {
    id: 'MUADDIB-SANDBOX-003',
    name: 'Sandbox: Suspicious Filesystem Change',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Package creates files in suspicious system locations during install',
    references: ['https://attack.mitre.org/techniques/T1543/'],
    mitre: 'T1543'
  },
  sandbox_suspicious_dns: {
    id: 'MUADDIB-SANDBOX-004',
    name: 'Sandbox: Suspicious DNS Query',
    severity: 'HIGH',
    confidence: 'medium',
    description: 'Package resolves non-registry domain during install',
    references: ['https://attack.mitre.org/techniques/T1071/'],
    mitre: 'T1071'
  },
  sandbox_suspicious_connection: {
    id: 'MUADDIB-SANDBOX-005',
    name: 'Sandbox: Suspicious Network Connection',
    severity: 'HIGH',
    confidence: 'medium',
    description: 'Package makes TCP connection to non-registry host during install',
    references: ['https://attack.mitre.org/techniques/T1071/'],
    mitre: 'T1071'
  },
  sandbox_suspicious_process: {
    id: 'MUADDIB-SANDBOX-006',
    name: 'Sandbox: Dangerous Process Spawned',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Package spawns dangerous command during install (curl, wget, nc, etc.)',
    references: ['https://attack.mitre.org/techniques/T1059/'],
    mitre: 'T1059'
  },
  sandbox_unknown_process: {
    id: 'MUADDIB-SANDBOX-007',
    name: 'Sandbox: Unknown Process Spawned',
    severity: 'MEDIUM',
    confidence: 'low',
    description: 'Package spawns unrecognized process during install',
    references: ['https://attack.mitre.org/techniques/T1059/'],
    mitre: 'T1059'
  },
  sandbox_timeout: {
    id: 'MUADDIB-SANDBOX-008',
    name: 'Sandbox: Container Timeout',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Package install exceeded sandbox timeout - possible infinite loop or resource exhaustion',
    references: ['https://attack.mitre.org/techniques/T1499/'],
    mitre: 'T1499'
  },
};

function getRule(type) {
  if (RULES[type]) return RULES[type];
  if (PARANOID_RULES[type]) return PARANOID_RULES[type];
  return {
    id: 'MUADDIB-UNK-001',
    name: 'Unknown Threat',
    severity: 'MEDIUM',
    confidence: 'low',
    description: 'Menace non categorisee',
    references: [],
    mitre: null
  };
}

// Paranoid rules (ultra-strict)
const PARANOID_RULES = {
  network_access: {
    id: 'MUADDIB-PARANOID-001',
    severity: 'HIGH',
    patterns: ['fetch', 'axios', 'http.request', 'https.request', 'net.connect', 'XMLHttpRequest'],
    message: 'Network access detected (paranoid mode)',
    mitre: 'T1071'
  },
  sensitive_file_access: {
    id: 'MUADDIB-PARANOID-002',
    severity: 'HIGH',
    patterns: ['.env', '.npmrc', '.ssh', '.git', 'id_rsa', 'credentials', 'secrets'],
    message: 'Sensitive file access detected (paranoid mode)',
    mitre: 'T1552.001'
  },
  dynamic_execution: {
    id: 'MUADDIB-PARANOID-003',
    severity: 'CRITICAL',
    patterns: ['eval', 'Function', 'vm.runInContext'],
    message: 'Dynamic code execution detected (paranoid mode)',
    mitre: 'T1059'
  },
  subprocess: {
    id: 'MUADDIB-PARANOID-004',
    severity: 'CRITICAL',
    patterns: ['child_process', 'spawn', 'exec', 'execSync', 'spawnSync', 'fork'],
    message: 'Subprocess execution detected (paranoid mode)',
    mitre: 'T1059.004'
  },
  env_access: {
    id: 'MUADDIB-PARANOID-005',
    severity: 'MEDIUM',
    patterns: ['process.env'],
    message: 'Environment variable access detected (paranoid mode)',
    mitre: 'T1552.001'
  }
};

module.exports = { RULES, getRule, PARANOID_RULES };