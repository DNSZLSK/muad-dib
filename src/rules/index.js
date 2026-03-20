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
  dependency_url_suspicious: {
    id: 'MUADDIB-DEP-005',
    name: 'Suspicious Dependency URL',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Dependance declaree avec une URL HTTP/HTTPS au lieu d\'une version npm. Les URLs ngrok/localhost/IP privee sont fortement suspectes.',
    references: [
      'https://docs.npmjs.com/cli/v9/configuring-npm/package-json#urls-as-dependencies'
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
  python_reverse_shell: {
    id: 'MUADDIB-SHELL-010',
    name: 'Python Reverse Shell',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Reverse shell via python -c import socket detecte',
    references: ['https://attack.mitre.org/techniques/T1059/004/'],
    mitre: 'T1059.006'
  },
  perl_reverse_shell: {
    id: 'MUADDIB-SHELL-011',
    name: 'Perl Reverse Shell',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Reverse shell via perl -e socket detecte',
    references: ['https://attack.mitre.org/techniques/T1059/004/'],
    mitre: 'T1059.006'
  },
  fifo_reverse_shell: {
    id: 'MUADDIB-SHELL-012',
    name: 'FIFO Reverse Shell',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Reverse shell via mkfifo /dev/tcp detecte',
    references: ['https://attack.mitre.org/techniques/T1059/004/'],
    mitre: 'T1059.004'
  },
  fifo_nc_reverse_shell: {
    id: 'MUADDIB-SHELL-013',
    name: 'FIFO + Netcat Reverse Shell',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Reverse shell via mkfifo + netcat (sans /dev/tcp). Technique alternative de reverse shell utilisant un named pipe.',
    references: ['https://attack.mitre.org/techniques/T1059/004/'],
    mitre: 'T1059.004'
  },
  base64_decode_exec: {
    id: 'MUADDIB-SHELL-014',
    name: 'Base64 Decode Pipe to Shell',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Payload encode en base64 decode et pipe vers bash/sh. Technique d\'obfuscation courante pour cacher des commandes malveillantes.',
    references: ['https://attack.mitre.org/techniques/T1140/'],
    mitre: 'T1140'
  },
  wget_base64_decode: {
    id: 'MUADDIB-SHELL-015',
    name: 'Wget + Base64 Decode',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Telechargement via wget suivi de decodage base64. Pattern de staging en deux etapes pour dropper un payload.',
    references: ['https://attack.mitre.org/techniques/T1105/'],
    mitre: 'T1105'
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
  dynamic_require: {
    id: 'MUADDIB-AST-006',
    name: 'Dynamic Require with Concatenation',
    severity: 'HIGH',
    confidence: 'high',
    description: 'require() avec concatenation de chaines — technique d\'obfuscation pour masquer le nom du module',
    references: ['https://attack.mitre.org/techniques/T1027/'],
    mitre: 'T1027'
  },
  dangerous_exec: {
    id: 'MUADDIB-AST-007',
    name: 'Dangerous Shell Command Execution',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'exec() avec commande shell dangereuse (pipe to shell, reverse shell, netcat)',
    references: ['https://owasp.org/www-community/attacks/Command_Injection'],
    mitre: 'T1059.004'
  },
  staged_payload: {
    id: 'MUADDIB-FLOW-002',
    name: 'Staged Payload Execution',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Telechargement reseau + eval() dans le meme fichier — execution de payload distant',
    references: ['https://attack.mitre.org/techniques/T1105/'],
    mitre: 'T1105'
  },
  network_require: {
    id: 'MUADDIB-PKG-011',
    name: 'Network Module in Lifecycle Script',
    severity: 'HIGH',
    confidence: 'high',
    description: 'require(https/http) dans un script lifecycle — telechargement au moment de l\'installation',
    references: ['https://blog.phylum.io/shai-hulud-npm-worm'],
    mitre: 'T1105'
  },
  node_inline_exec: {
    id: 'MUADDIB-PKG-012',
    name: 'Node Inline Execution in Lifecycle Script',
    severity: 'HIGH',
    confidence: 'high',
    description: 'node -e dans un script lifecycle — execution de code inline au moment de l\'installation',
    references: ['https://owasp.org/www-community/attacks/Command_Injection'],
    mitre: 'T1059.007'
  },
  dynamic_import: {
    id: 'MUADDIB-AST-008',
    name: 'Dynamic import() of Dangerous Module',
    severity: 'HIGH',
    confidence: 'high',
    description: 'import() dynamique pour charger un module dangereux ou avec argument calcule — technique d\'evasion pour eviter la detection de require()',
    references: ['https://attack.mitre.org/techniques/T1027/'],
    mitre: 'T1027'
  },
  env_proxy_intercept: {
    id: 'MUADDIB-AST-009',
    name: 'Environment Variable Proxy Interception',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'new Proxy(process.env) detecte — intercepte silencieusement tous les acces aux variables d\'environnement pour exfiltration',
    references: ['https://attack.mitre.org/techniques/T1552/001/'],
    mitre: 'T1552.001'
  },
  dynamic_require_exec: {
    id: 'MUADDIB-AST-010',
    name: 'Command Execution via Dynamic Require',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'exec/execSync appele sur un module charge dynamiquement (require obfusque) — execution de commandes dissimulees',
    references: ['https://attack.mitre.org/techniques/T1059/007/'],
    mitre: 'T1059.007'
  },
  sandbox_evasion: {
    id: 'MUADDIB-AST-011',
    name: 'Sandbox/Container Evasion',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Detection de sandbox/container (/.dockerenv, /proc/cgroup) — technique anti-analyse pour eviter la detection en environnement controle',
    references: ['https://attack.mitre.org/techniques/T1497/001/'],
    mitre: 'T1497.001'
  },
  detached_process: {
    id: 'MUADDIB-AST-012',
    name: 'Detached Background Process',
    severity: 'HIGH',
    confidence: 'high',
    description: 'spawn/fork avec {detached: true} — le processus survit a la fin de npm install et execute le payload en arriere-plan',
    references: ['https://attack.mitre.org/techniques/T1036/009/'],
    mitre: 'T1036.009'
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

  credential_command_exec: {
    id: 'MUADDIB-AST-014',
    name: 'Credential Theft via CLI Tool',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'exec/execSync appelle un outil CLI legitime pour voler des tokens d\'authentification (gh auth token, gcloud auth, aws sts). Technique s1ngularity/Nx.',
    references: [
      'https://snyk.io/blog/malicious-npm-packages-abuse-ai-agents/',
      'https://attack.mitre.org/techniques/T1059/'
    ],
    mitre: 'T1059'
  },
  workflow_write: {
    id: 'MUADDIB-AST-015',
    name: 'GitHub Actions Workflow Write',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'fs.writeFileSync cree un fichier dans .github/workflows — injection de workflow GitHub Actions pour persistence. Technique Shai-Hulud 2.0.',
    references: [
      'https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack',
      'https://attack.mitre.org/techniques/T1195/002/'
    ],
    mitre: 'T1195.002'
  },
  binary_dropper: {
    id: 'MUADDIB-AST-016',
    name: 'Binary Dropper Pattern',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'fs.chmodSync avec permissions executables (0o755/0o777) — pattern de dropper binaire: telecharge, ecrit, chmod, execute.',
    references: [
      'https://www.sonatype.com/blog/phantomraven-supply-chain-attack',
      'https://attack.mitre.org/techniques/T1105/'
    ],
    mitre: 'T1105'
  },
  prototype_hook: {
    id: 'MUADDIB-AST-017',
    name: 'Native API Prototype Hooking',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Modification du prototype ou remplacement de fonctions natives du navigateur/Node.js (fetch, XMLHttpRequest, http.request). Technique chalk/debug (Sygnia, sept 2025) pour intercepter du trafic.',
    references: [
      'https://www.sygnia.co/blog/malicious-chalk-debug-npm-packages/',
      'https://attack.mitre.org/techniques/T1557/'
    ],
    mitre: 'T1557'
  },

  ai_config_injection: {
    id: 'MUADDIB-AICONF-001',
    name: 'AI Config Prompt Injection',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Fichier de configuration d\'agent IA (.cursorrules, CLAUDE.md, copilot-instructions.md) contient des instructions d\'execution de commandes shell ou d\'acces a des credentials. Technique ToxicSkills/Clinejection.',
    references: [
      'https://snyk.io/blog/toxicskills-prompt-injection-ai-agents/',
      'https://snyk.io/blog/clinejection-ai-config-prompt-injection/',
      'https://arxiv.org/abs/2601.17548'
    ],
    mitre: 'T1059'
  },
  ai_config_injection_critical: {
    id: 'MUADDIB-AICONF-002',
    name: 'AI Config Prompt Injection (Critical)',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Fichier de configuration d\'agent IA contient des commandes d\'exfiltration (curl POST vers un domaine externe, pipe vers shell) ou une combinaison commande shell + acces credentials. Attaque confirmee.',
    references: [
      'https://snyk.io/blog/toxicskills-prompt-injection-ai-agents/',
      'https://snyk.io/blog/clinejection-ai-config-prompt-injection/',
      'https://arxiv.org/abs/2601.17548',
      'https://developer.nvidia.com/blog/ai-agent-security-guidance/'
    ],
    mitre: 'T1059'
  },

  require_cache_poison: {
    id: 'MUADDIB-AST-019',
    name: 'Require Cache Poisoning',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Acces a require.cache pour remplacer ou hijacker des modules Node.js charges. Technique de cache poisoning pour intercepter du trafic ou injecter du code.',
    references: [
      'https://attack.mitre.org/techniques/T1574/006/'
    ],
    mitre: 'T1574.006'
  },
  staged_binary_payload: {
    id: 'MUADDIB-AST-020',
    name: 'Staged Binary Payload Execution',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Reference a un fichier binaire (.png/.jpg/.wasm) combinee avec eval() dans le meme fichier. Possible execution de payload steganographique cache dans une image.',
    references: [
      'https://attack.mitre.org/techniques/T1027/003/'
    ],
    mitre: 'T1027.003'
  },

  staged_eval_decode: {
    id: 'MUADDIB-AST-021',
    name: 'Staged Eval Decode',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'eval() ou Function() recoit un argument decode (atob ou Buffer.from base64). Pattern classique de staged payload: le code malveillant est encode en base64 puis decode et execute dynamiquement.',
    references: [
      'https://attack.mitre.org/techniques/T1140/',
      'https://attack.mitre.org/techniques/T1059/007/'
    ],
    mitre: 'T1140'
  },

  env_charcode_reconstruction: {
    id: 'MUADDIB-AST-018',
    name: 'Environment Variable Key Reconstruction',
    severity: 'HIGH',
    confidence: 'high',
    description: 'process.env accede avec une cle reconstruite dynamiquement via String.fromCharCode. Technique d\'obfuscation pour eviter la detection statique des noms de variables sensibles (GITHUB_TOKEN, etc.).',
    references: [
      'https://attack.mitre.org/techniques/T1027/',
      'https://attack.mitre.org/techniques/T1552/001/'
    ],
    mitre: 'T1027'
  },

  lifecycle_hidden_payload: {
    id: 'MUADDIB-PKG-016',
    name: 'Lifecycle Script Targets Hidden Payload',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Script lifecycle pointe vers un fichier dans node_modules/ — technique de dissimulation de payload. Les scanners excluent node_modules/ par defaut, rendant le payload invisible. Pattern DPRK/Lazarus interview attack.',
    references: [
      'https://unit42.paloaltonetworks.com/operation-dream-job/',
      'https://blog.phylum.io/shai-hulud-npm-worm'
    ],
    mitre: 'T1027.009'
  },

  lifecycle_shell_pipe: {
    id: 'MUADDIB-PKG-010',
    name: 'Lifecycle Script Pipes to Shell',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Script lifecycle (preinstall/install/postinstall) execute curl | sh ou wget | bash — telecharge et execute du code distant au moment de npm install.',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm',
      'https://socket.dev/blog/2025-supply-chain-report'
    ],
    mitre: 'T1195.002'
  },

  cross_file_dataflow: {
    id: 'MUADDIB-FLOW-004',
    name: 'Cross-File Data Exfiltration',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Un module lit des credentials (fs.readFileSync, process.env) et les exporte vers un autre module qui les envoie sur le reseau (fetch, https.request). Exfiltration inter-fichiers confirmee.',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm',
      'https://attack.mitre.org/techniques/T1041/'
    ],
    mitre: 'T1041'
  },

  credential_tampering: {
    id: 'MUADDIB-FLOW-003',
    name: 'Credential/Cache Tampering',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Ecriture dans un chemin sensible (cache npm _cacache, cache yarn, credentials). Possible cache poisoning: injection de code malveillant dans des packages caches.',
    references: [
      'https://attack.mitre.org/techniques/T1565/001/'
    ],
    mitre: 'T1565.001'
  },

  crypto_decipher: {
    id: 'MUADDIB-AST-022',
    name: 'Encrypted Payload Decryption',
    severity: 'HIGH',
    confidence: 'high',
    description: 'crypto.createDecipher/createDecipheriv detecte. Dechiffrement runtime de payload embarque. Pattern canonique de flatmap-stream/event-stream.',
    references: [
      'https://snyk.io/blog/malicious-code-found-in-npm-package-event-stream/',
      'https://attack.mitre.org/techniques/T1140/'
    ],
    mitre: 'T1140'
  },

  module_compile: {
    id: 'MUADDIB-AST-023',
    name: 'Module Compile Execution',
    severity: 'HIGH',
    confidence: 'high',
    description: 'module._compile() detecte. Execution de code arbitraire a partir d\'une chaine dans le contexte module. Technique cle de flatmap-stream.',
    references: [
      'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident',
      'https://attack.mitre.org/techniques/T1059/007/'
    ],
    mitre: 'T1059'
  },

  zlib_inflate_eval: {
    id: 'MUADDIB-AST-024',
    name: 'Obfuscated Payload via Zlib Inflate',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Payload obfusque: zlib inflate + decodage base64 + execution dynamique (eval/Function/Module._compile) dans le meme fichier. Aucun package legitime n\'utilise ce pattern. Technique SANDWORM_MODE (fev. 2026).',
    references: [
      'https://socket.dev/blog/sandworm-mode-campaign',
      'https://attack.mitre.org/techniques/T1027/002/'
    ],
    mitre: 'T1027.002'
  },

  module_compile_dynamic: {
    id: 'MUADDIB-AST-025',
    name: 'Dynamic Module Compile Execution',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Module._compile() avec argument dynamique (non-literal). Execution de code en memoire sans ecriture sur disque. Technique d\'evasion malware courante.',
    references: [
      'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident',
      'https://attack.mitre.org/techniques/T1059/007/'
    ],
    mitre: 'T1059'
  },

  write_execute_delete: {
    id: 'MUADDIB-AST-026',
    name: 'Anti-Forensics Write-Execute-Delete',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Anti-forensique: ecriture dans un repertoire temporaire, execution, puis suppression. Pattern typique de staging malware pour eviter la detection post-mortem.',
    references: [
      'https://attack.mitre.org/techniques/T1070/004/'
    ],
    mitre: 'T1070.004'
  },

  mcp_config_injection: {
    id: 'MUADDIB-AST-027',
    name: 'MCP Config Injection',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Injection de configuration MCP: ecriture dans les fichiers de configuration d\'assistants IA (.claude/, .cursor/, .continue/, .vscode/, .windsurf/). Technique SANDWORM_MODE pour empoisonner la chaine d\'outils IA.',
    references: [
      'https://attack.mitre.org/techniques/T1546/016/'
    ],
    mitre: 'T1546.016'
  },

  git_hooks_injection: {
    id: 'MUADDIB-AST-028',
    name: 'Git Hooks Injection',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Injection de hooks Git: ecriture dans .git/hooks/ ou modification de git config init.templateDir. Technique de persistence via hooks pre-commit, pre-push, post-checkout.',
    references: [
      'https://attack.mitre.org/techniques/T1546/004/'
    ],
    mitre: 'T1546.004'
  },

  env_harvesting_dynamic: {
    id: 'MUADDIB-AST-029',
    name: 'Dynamic Environment Variable Harvesting',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Collecte dynamique de variables d\'environnement via Object.entries/keys/values(process.env) avec filtrage par patterns sensibles (TOKEN, SECRET, KEY, PASSWORD, AWS, SSH). Technique de vol de credentials.',
    references: [
      'https://attack.mitre.org/techniques/T1552/001/'
    ],
    mitre: 'T1552.001'
  },

  dns_chunk_exfiltration: {
    id: 'MUADDIB-AST-030',
    name: 'DNS Chunk Exfiltration',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Exfiltration DNS: donnees encodees en base64 dans les requetes DNS. Canal covert pour contourner les firewalls. Pattern: dns.resolve + Buffer.from().toString("base64").',
    references: [
      'https://attack.mitre.org/techniques/T1048/003/'
    ],
    mitre: 'T1048.003'
  },

  llm_api_key_harvesting: {
    id: 'MUADDIB-AST-031',
    name: 'LLM API Key Harvesting',
    severity: 'MEDIUM',
    confidence: 'medium',
    description: 'Collecte de cles API LLM: acces a 3+ variables d\'environnement de providers IA (OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY, etc.). Vecteur de monetisation.',
    references: [
      'https://attack.mitre.org/techniques/T1552/001/'
    ],
    mitre: 'T1552.001'
  },

  ai_agent_abuse: {
    id: 'MUADDIB-AST-013',
    name: 'AI Agent Weaponization',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Invocation d\'un agent IA (Claude, Gemini, Q, Aider) avec des flags qui desactivent les controles de securite (--dangerously-skip-permissions, --yolo, --trust-all-tools). Technique s1ngularity/Nx (aout 2025).',
    references: [
      'https://snyk.io/blog/malicious-npm-packages-abuse-ai-agents/',
      'https://stepsecurity.io/blog/ai-agent-weaponization-supply-chain',
      'https://attack.mitre.org/techniques/T1059/'
    ],
    mitre: 'T1059'
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
  workflow_pwn_request: {
    id: 'MUADDIB-GHA-003',
    name: 'GitHub Actions Pwn Request',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Workflow pull_request_target avec checkout du head ref/sha de la PR — permet execution de code arbitraire (pwn request)',
    references: [
      'https://securitylab.github.com/research/github-actions-preventing-pwn-requests/',
      'https://attack.mitre.org/techniques/T1195/002/'
    ],
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

  // Sandbox preload detections (time-bomb and behavioral analysis)
  sandbox_timer_delay_suspicious: {
    id: 'MUADDIB-SANDBOX-009',
    name: 'Sandbox: Suspicious Timer Delay',
    severity: 'MEDIUM',
    confidence: 'medium',
    description: 'Package uses setTimeout/setInterval with delay > 1 hour. Possible time-bomb to evade sandbox analysis.',
    references: ['https://attack.mitre.org/techniques/T1497/003/'],
    mitre: 'T1497.003'
  },
  sandbox_timer_delay_critical: {
    id: 'MUADDIB-SANDBOX-010',
    name: 'Sandbox: Critical Timer Delay (Time-Bomb)',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Package uses setTimeout/setInterval with delay > 24 hours. Strong indicator of time-bomb malware designed to evade sandbox analysis.',
    references: ['https://attack.mitre.org/techniques/T1497/003/'],
    mitre: 'T1497.003'
  },
  sandbox_preload_sensitive_read: {
    id: 'MUADDIB-SANDBOX-011',
    name: 'Sandbox: Preload Sensitive File Read',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Package reads sensitive credential files (.npmrc, .ssh, .aws, .env) detected via runtime monkey-patching.',
    references: ['https://attack.mitre.org/techniques/T1552/001/'],
    mitre: 'T1552.001'
  },
  sandbox_network_after_sensitive_read: {
    id: 'MUADDIB-SANDBOX-012',
    name: 'Sandbox: Network After Sensitive Read',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Package makes network requests after reading sensitive files. Strong indicator of credential exfiltration.',
    references: ['https://attack.mitre.org/techniques/T1041/'],
    mitre: 'T1041'
  },
  sandbox_exec_suspicious: {
    id: 'MUADDIB-SANDBOX-013',
    name: 'Sandbox: Suspicious Command Execution',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Package executes dangerous commands (curl, wget, bash, sh, powershell) detected via runtime monkey-patching.',
    references: ['https://attack.mitre.org/techniques/T1059/'],
    mitre: 'T1059'
  },
  sandbox_env_token_access: {
    id: 'MUADDIB-SANDBOX-014',
    name: 'Sandbox: Sensitive Env Var Access',
    severity: 'MEDIUM',
    confidence: 'medium',
    description: 'Package accesses sensitive environment variables (TOKEN, SECRET, KEY, PASSWORD) detected via runtime monkey-patching.',
    references: ['https://attack.mitre.org/techniques/T1552/001/'],
    mitre: 'T1552.001'
  },

  // Entropy detections
  high_entropy_string: {
    id: 'MUADDIB-ENTROPY-001',
    name: 'High Entropy String',
    severity: 'MEDIUM',
    confidence: 'medium',
    description: 'Chaine a haute entropie detectee (base64, hex, payload chiffre). Souvent signe d\'obfuscation ou de donnees encodees.',
    references: ['https://attack.mitre.org/techniques/T1027/'],
    mitre: 'T1027'
  },
  fragmented_high_entropy_cluster: {
    id: 'MUADDIB-ENTROPY-004',
    name: 'Fragmented High Entropy Cluster',
    severity: 'MEDIUM',
    confidence: 'medium',
    description: 'Cluster de chaines courtes a haute entropie (8-49 chars) detecte. Technique de fragmentation de payload pour contourner le seuil de longueur minimum d\'analyse entropique.',
    references: ['https://attack.mitre.org/techniques/T1027/'],
    mitre: 'T1027'
  },
  js_obfuscation_pattern: {
    id: 'MUADDIB-ENTROPY-003',
    name: 'JS Obfuscation Pattern',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Pattern d\'obfuscation JS detecte: variables _0x*, tableaux de strings encodes, eval/Function avec contenu haute entropie, ou long payload base64. Signature de javascript-obfuscator et malwares npm connus.',
    references: [
      'https://attack.mitre.org/techniques/T1027/002/',
      'https://attack.mitre.org/techniques/T1027/010/',
      'https://blog.phylum.io/shai-hulud-npm-worm'
    ],
    mitre: 'T1027.002'
  },

  // Temporal analysis detections
  lifecycle_added_critical: {
    id: 'MUADDIB-TEMPORAL-001',
    name: 'Sudden Lifecycle Script Added (Critical)',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Script preinstall/install/postinstall ajoute dans la derniere version. Vecteur d\'attaque #1 des supply chain attacks (Shai-Hulud, ua-parser-js, coa).',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm',
      'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident',
      'https://github.com/nicedayfor/yargs-parser/security/advisories'
    ],
    mitre: 'T1195.002'
  },
  lifecycle_added_high: {
    id: 'MUADDIB-TEMPORAL-002',
    name: 'Sudden Lifecycle Script Added',
    severity: 'HIGH',
    confidence: 'medium',
    description: 'Script lifecycle (prepare, prepack, etc.) ajoute dans la derniere version. Potentiellement suspect si non justifie.',
    references: [
      'https://docs.npmjs.com/cli/v9/using-npm/scripts#life-cycle-scripts',
      'https://blog.phylum.io/shai-hulud-npm-worm'
    ],
    mitre: 'T1195.002'
  },
  lifecycle_modified: {
    id: 'MUADDIB-TEMPORAL-003',
    name: 'Lifecycle Script Modified',
    severity: 'MEDIUM',
    confidence: 'medium',
    description: 'Script lifecycle modifie entre les deux dernieres versions. Verifier si le changement est legitime.',
    references: [
      'https://docs.npmjs.com/cli/v9/using-npm/scripts#life-cycle-scripts'
    ],
    mitre: 'T1195.002'
  },

  // Temporal AST diff detections
  dangerous_api_added_critical: {
    id: 'MUADDIB-TEMPORAL-AST-001',
    name: 'Dangerous API Added (Critical)',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'API dangereuse (child_process, eval, Function, net.connect) apparue dans la derniere version. Absente de la version precedente.',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm',
      'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident'
    ],
    mitre: 'T1195.002'
  },
  dangerous_api_added_high: {
    id: 'MUADDIB-TEMPORAL-AST-002',
    name: 'Dangerous API Added (High)',
    severity: 'HIGH',
    confidence: 'medium',
    description: 'API suspecte (process.env, fetch, http/https) apparue dans la derniere version. Absente de la version precedente.',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm',
      'https://docs.npmjs.com/cli/v9/using-npm/scripts#life-cycle-scripts'
    ],
    mitre: 'T1195.002'
  },
  dangerous_api_added_medium: {
    id: 'MUADDIB-TEMPORAL-AST-003',
    name: 'Dangerous API Added (Medium)',
    severity: 'MEDIUM',
    confidence: 'medium',
    description: 'API potentiellement suspecte (dns.lookup, fs.readFile sur chemin sensible) apparue dans la derniere version.',
    references: [
      'https://docs.npmjs.com/cli/v9/using-npm/scripts#life-cycle-scripts'
    ],
    mitre: 'T1195.002'
  },

  // Publish frequency anomaly detections
  publish_burst: {
    id: 'MUADDIB-PUBLISH-001',
    name: 'Publish Burst Detected',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Multiple versions publiees en moins de 24h. Possible compromission de compte ou attaque automatisee.',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm',
      'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident'
    ],
    mitre: 'T1195.002'
  },
  dormant_spike: {
    id: 'MUADDIB-PUBLISH-002',
    name: 'Dormant Package Spike',
    severity: 'HIGH',
    confidence: 'medium',
    description: 'Package inactif depuis 6+ mois avec une nouvelle version soudaine. Possible changement de mainteneur ou compromission.',
    references: [
      'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident',
      'https://snyk.io/blog/malicious-npm-packages-targeting-developers/'
    ],
    mitre: 'T1195.002'
  },
  rapid_succession: {
    id: 'MUADDIB-PUBLISH-003',
    name: 'Rapid Version Succession',
    severity: 'MEDIUM',
    confidence: 'medium',
    description: 'Versions publiees en succession rapide (moins d\'1h). Possible attaque automatisee ou CI/CD compromis.',
    references: [
      'https://docs.npmjs.com/cli/v9/using-npm/scripts#life-cycle-scripts'
    ],
    mitre: 'T1195.002'
  },

  // Maintainer change detections
  new_maintainer: {
    id: 'MUADDIB-MAINTAINER-001',
    name: 'New Maintainer Added',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Un nouveau maintainer a ete ajoute au package entre les deux dernieres versions. Verifier si le changement est legitime.',
    references: [
      'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident',
      'https://snyk.io/blog/malicious-npm-packages-targeting-developers/'
    ],
    mitre: 'T1195.002'
  },
  suspicious_maintainer: {
    id: 'MUADDIB-MAINTAINER-002',
    name: 'Suspicious Maintainer Detected',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Maintainer avec un nom suspect (generique, auto-genere, tres court). Risque eleve de compromission de compte.',
    references: [
      'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident',
      'https://blog.phylum.io/shai-hulud-npm-worm'
    ],
    mitre: 'T1195.002'
  },
  sole_maintainer_change: {
    id: 'MUADDIB-MAINTAINER-003',
    name: 'Sole Maintainer Changed',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Le seul maintainer du package a change. Indicateur fort de compromission de compte (event-stream attack pattern).',
    references: [
      'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident',
      'https://snyk.io/blog/malicious-npm-packages-targeting-developers/'
    ],
    mitre: 'T1195.002'
  },
  new_publisher: {
    id: 'MUADDIB-MAINTAINER-004',
    name: 'New Publisher Detected',
    severity: 'MEDIUM',
    confidence: 'medium',
    description: 'La derniere version a ete publiee par un utilisateur different de la version precedente. Verifier la legitimite.',
    references: [
      'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident'
    ],
    mitre: 'T1195.002'
  },

  // Canary token detections
  canary_exfiltration: {
    id: 'MUADDIB-CANARY-001',
    name: 'Canary Token Exfiltration',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Le package a tente d\'exfiltrer des honey tokens (faux secrets) injectes dans le sandbox. Comportement malveillant confirme.',
    references: [
      'https://canarytokens.org/generate',
      'https://blog.phylum.io/shai-hulud-npm-worm'
    ],
    mitre: 'T1552.001'
  },

  suspicious_domain: {
    id: 'MUADDIB-AST-032',
    name: 'Suspicious C2/Exfiltration Domain',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Domaine C2 ou d\'exfiltration detecte dans le code (oastify.com, burpcollaborator.net, webhook.site, ngrok.io, etc.). Ces domaines sont utilises pour recevoir des donnees volees ou comme relais de commande.',
    references: [
      'https://attack.mitre.org/techniques/T1071/001/',
      'https://portswigger.net/burp/documentation/collaborator'
    ],
    mitre: 'T1071.001'
  },

  fetch_decrypt_exec: {
    id: 'MUADDIB-AST-033',
    name: 'Steganographic Payload Chain',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Chaine steganographique: fetch distant + dechiffrement crypto + execution dynamique (eval/Function). Pattern buildrunner-dev: payload cache dans une image, dechiffre a runtime, puis execute.',
    references: [
      'https://attack.mitre.org/techniques/T1027/003/',
      'https://attack.mitre.org/techniques/T1140/'
    ],
    mitre: 'T1027.003'
  },

  download_exec_binary: {
    id: 'MUADDIB-AST-034',
    name: 'Download-Execute Binary Pattern',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Pattern download-execute: telechargement distant + chmod executable + execSync dans le meme fichier. Dropper binaire deguise en compilation native addon (NeoShadow pattern).',
    references: [
      'https://attack.mitre.org/techniques/T1105/',
      'https://attack.mitre.org/techniques/T1059/'
    ],
    mitre: 'T1105'
  },

  ide_persistence: {
    id: 'MUADDIB-AST-035',
    name: 'IDE Task Persistence',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Persistence IDE: ecriture dans tasks.json ou Code/User/ avec execution automatique a l\'ouverture du dossier (runOn: folderOpen). Pattern FAMOUS CHOLLIMA / StegaBin pour persistance VS Code.',
    references: [
      'https://attack.mitre.org/techniques/T1546/'
    ],
    mitre: 'T1546'
  },

  vm_code_execution: {
    id: 'MUADDIB-AST-036',
    name: 'VM Module Code Execution',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Execution de code dynamique via le module vm de Node.js (vm.runInThisContext, vm.runInNewContext, vm.compileFunction, new vm.Script). Contourne la detection eval/Function.',
    references: [
      'https://nodejs.org/api/vm.html',
      'https://attack.mitre.org/techniques/T1059/'
    ],
    mitre: 'T1059'
  },

  reflect_code_execution: {
    id: 'MUADDIB-AST-037',
    name: 'Reflect API Code Execution',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Execution de code dynamique via Reflect.construct(Function, [...]) ou Reflect.apply(eval, ...). Contourne la detection directe de eval/Function/new Function.',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Reflect',
      'https://attack.mitre.org/techniques/T1059/'
    ],
    mitre: 'T1059'
  },

  process_binding_abuse: {
    id: 'MUADDIB-AST-038',
    name: 'Process Binding Abuse',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Acces direct aux bindings V8 internes via process.binding() ou process._linkedBinding(). Contourne les modules child_process/fs pour execution de commandes ou acces fichiers sans detection.',
    references: [
      'https://nodejs.org/api/process.html#processbindingname',
      'https://attack.mitre.org/techniques/T1059/'
    ],
    mitre: 'T1059'
  },

  worker_thread_exec: {
    id: 'MUADDIB-AST-039',
    name: 'Worker Thread Code Execution',
    severity: 'HIGH',
    confidence: 'high',
    description: 'new Worker() avec eval:true execute du code arbitraire dans un thread worker, contournant la detection du thread principal. Technique d\'evasion pour executer du code dynamique hors du scope AST principal.',
    references: [
      'https://nodejs.org/api/worker_threads.html',
      'https://attack.mitre.org/techniques/T1059/'
    ],
    mitre: 'T1059'
  },
  wasm_host_sink: {
    id: 'MUADDIB-AST-042',
    name: 'WASM Host Import Sink',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Module WebAssembly charge avec des callbacks host contenant des sinks reseau (fetch/http.request). Le WASM peut invoquer ces callbacks pour exfiltrer des donnees tout en cachant le flux de controle. Aucun package npm legitime ne combine WASM + callbacks reseau host.',
    references: [
      'https://attack.mitre.org/techniques/T1059/',
      'https://attack.mitre.org/techniques/T1027/'
    ],
    mitre: 'T1059'
  },
  wasm_standalone: {
    id: 'MUADDIB-AST-046',
    name: 'WASM Module Load (Standalone)',
    severity: 'MEDIUM',
    confidence: 'medium',
    description: 'Module WebAssembly charge sans sink reseau detectable. Usage legitime frequent (cryptographie, traitement d\'image, codecs). Le WASM cache le flux de controle — verifier le fichier .wasm manuellement.',
    references: ['https://attack.mitre.org/techniques/T1027/'],
    mitre: 'T1027'
  },
  credential_regex_harvest: {
    id: 'MUADDIB-AST-041',
    name: 'Credential Regex Harvesting',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Regex de detection de credentials (token/password/secret/Bearer) combine avec un appel reseau. Technique de harvesting: le code scanne les donnees de flux (streams, requetes) a la recherche de credentials et les exfiltre.',
    references: [
      'https://attack.mitre.org/techniques/T1552/',
      'https://attack.mitre.org/techniques/T1041/'
    ],
    mitre: 'T1552'
  },
  builtin_override_exfil: {
    id: 'MUADDIB-AST-044',
    name: 'Built-in Method Override Exfiltration',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Override de methode built-in (console.log/warn/error, Object.defineProperty) combine avec un appel reseau. Technique de monkey-patching: le code remplace une API native pour intercepter les donnees en transit et les exfiltrer.',
    references: [
      'https://attack.mitre.org/techniques/T1557/',
      'https://attack.mitre.org/techniques/T1041/'
    ],
    mitre: 'T1557'
  },
  stream_credential_intercept: {
    id: 'MUADDIB-AST-045',
    name: 'Stream Credential Interception',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Classe stream (Transform/Duplex/Writable) avec regex de credentials et appel reseau. Technique de wiretap: le stream intercepte les donnees en transit, scanne pour des credentials (Bearer, password, token) et les exfiltre.',
    references: [
      'https://attack.mitre.org/techniques/T1557/',
      'https://attack.mitre.org/techniques/T1552/'
    ],
    mitre: 'T1557'
  },
  remote_code_load: {
    id: 'MUADDIB-AST-040',
    name: 'Remote Code Loading',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Fetch reseau + eval/Function dans le meme fichier. Technique multi-stage: le code telecharge un payload distant (SVG, HTML, JSON) et l\'execute dynamiquement. Aucun package npm legitime ne combine fetch + eval/Function.',
    references: [
      'https://attack.mitre.org/techniques/T1105/',
      'https://attack.mitre.org/techniques/T1059/'
    ],
    mitre: 'T1105'
  },
  proxy_data_intercept: {
    id: 'MUADDIB-AST-043',
    name: 'Proxy Data Interception',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Proxy trap (set/get/apply) combine avec un appel reseau dans le meme fichier. Technique d\'interception de donnees: le Proxy capture toutes les ecritures/lectures de proprietes et les exfiltre via le reseau. Utilise pour voler des credentials passees via module.exports.',
    references: [
      'https://attack.mitre.org/techniques/T1557/',
      'https://attack.mitre.org/techniques/T1041/'
    ],
    mitre: 'T1557'
  },
  // Package manifest detections (v2.8.9)
  bin_field_hijack: {
    id: 'MUADDIB-PKG-013',
    name: 'Bin Field PATH Hijack',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Le champ "bin" de package.json shadow une commande systeme (node, npm, git, bash, etc.). A l\'install, npm cree un symlink dans node_modules/.bin/ qui intercepte la commande reelle pour tous les npm scripts.',
    references: [
      'https://socket.dev/blog/2025-supply-chain-report',
      'https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack'
    ],
    mitre: 'T1574.007'
  },
  git_dependency_rce: {
    id: 'MUADDIB-PKG-014',
    name: 'Git Dependency RCE (PackageGate)',
    severity: 'HIGH',
    confidence: 'medium',
    description: 'Dependance utilisant une URL git+ ou git://. Vecteur PackageGate: un .npmrc malveillant peut overrider le binaire git, permettant l\'execution de code meme avec --ignore-scripts.',
    references: [
      'https://socket.dev/blog/packagegate-npm-rce',
      'https://attack.mitre.org/techniques/T1195/002/'
    ],
    mitre: 'T1195.002'
  },
  npmrc_git_override: {
    id: 'MUADDIB-PKG-015',
    name: '.npmrc Git Binary Override',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Fichier .npmrc contient git= override — technique PackageGate: remplace le binaire git par un script controle par l\'attaquant.',
    references: [
      'https://socket.dev/blog/packagegate-npm-rce'
    ],
    mitre: 'T1195.002'
  },

  // AST detections (v2.8.9 — supply-chain gaps)
  node_modules_write: {
    id: 'MUADDIB-AST-048',
    name: 'Write to node_modules/ (Worm Propagation)',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'writeFileSync/writeFile/appendFileSync ciblant node_modules/ — technique de propagation worm Shai-Hulud 2.0: modifie d\'autres packages installes pour injecter un backdoor persistent.',
    references: [
      'https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack',
      'https://attack.mitre.org/techniques/T1195/002/'
    ],
    mitre: 'T1195.002'
  },
  bun_runtime_evasion: {
    id: 'MUADDIB-AST-049',
    name: 'Bun Runtime Evasion',
    severity: 'HIGH',
    confidence: 'medium',
    description: 'Invocation du runtime Bun (bun run/exec/install) via exec/spawn — technique Shai-Hulud 2.0: utilise un runtime alternatif pour echapper aux sandboxes et monitoring Node.js.',
    references: [
      'https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack',
      'https://attack.mitre.org/techniques/T1059/'
    ],
    mitre: 'T1059'
  },
  static_timer_bomb: {
    id: 'MUADDIB-AST-050',
    name: 'Static Timer Bomb',
    severity: 'MEDIUM',
    confidence: 'medium',
    description: 'setTimeout/setInterval avec delai > 1h detecte statiquement. PhantomRaven active le 2nd stage 48h+ apres install. Evasion temporelle: le payload s\'active bien apres l\'installation pour echapper aux sandboxes.',
    references: [
      'https://www.sonatype.com/blog/phantomraven-supply-chain-attack',
      'https://attack.mitre.org/techniques/T1497/003/'
    ],
    mitre: 'T1497.003'
  },
  npm_publish_worm: {
    id: 'MUADDIB-AST-051',
    name: 'npm publish Worm Propagation',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'exec("npm publish") detecte — technique de propagation worm Shai-Hulud: utilise les tokens npm voles pour publier des versions infectees des packages de la victime.',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm',
      'https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack',
      'https://attack.mitre.org/techniques/T1195/002/'
    ],
    mitre: 'T1195.002'
  },
  ollama_local_llm: {
    id: 'MUADDIB-AST-052',
    name: 'Ollama Local LLM (Polymorphic Engine)',
    severity: 'HIGH',
    confidence: 'medium',
    description: 'Reference au port 11434 (Ollama) detectee. PhantomRaven Wave 4 utilise un LLM local pour reecrire le malware et eviter la detection signature. Moteur polymorphe.',
    references: [
      'https://www.sonatype.com/blog/phantomraven-supply-chain-attack',
      'https://attack.mitre.org/techniques/T1027/005/'
    ],
    mitre: 'T1027.005'
  },

  // Shell IFS evasion rules (v2.6.9)
  curl_ifs_evasion: {
    id: 'MUADDIB-SHELL-016',
    name: 'Curl IFS Variable Evasion',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Evasion IFS: curl$IFS ou curl${IFS} pipe vers shell. Technique d\'evasion pour contourner la detection de curl|sh en utilisant $IFS comme separateur.',
    references: ['https://attack.mitre.org/techniques/T1059/004/'],
    mitre: 'T1059.004'
  },
  eval_curl_subshell: {
    id: 'MUADDIB-SHELL-017',
    name: 'Eval Curl Command Substitution',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'eval $(curl ...) detecte. Telecharge et execute du code distant via command substitution.',
    references: ['https://attack.mitre.org/techniques/T1059/004/'],
    mitre: 'T1059.004'
  },
  sh_c_curl_exec: {
    id: 'MUADDIB-SHELL-018',
    name: 'Shell -c Curl Execution',
    severity: 'HIGH',
    confidence: 'high',
    description: 'sh -c wrapping autour de curl. Technique d\'evasion pour masquer l\'execution de commandes distantes.',
    references: ['https://attack.mitre.org/techniques/T1059/004/'],
    mitre: 'T1059.004'
  },

  // Intent Graph rules (v2.6.0)
  detached_credential_exfil: {
    id: 'MUADDIB-AST-047',
    name: 'Detached Process Credential Exfiltration',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Process detache (survit au parent) avec acces aux credentials et appel reseau — technique DPRK/Lazarus pour exfiltrer des secrets en arriere-plan',
    references: [
      'https://attack.mitre.org/techniques/T1041/',
      'https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a'
    ],
    mitre: 'T1041'
  },
  intent_credential_exfil: {
    id: 'MUADDIB-INTENT-001',
    name: 'Intent Credential Exfiltration',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Coherence d\'intention: lecture de credentials (fichiers sensibles, env vars) combinee avec un sink reseau ou exec dans le meme package. Pattern typique DPRK/Lazarus: code malveillant fragmente sur plusieurs fichiers avec uniquement des APIs legitimes.',
    references: [
      'https://attack.mitre.org/techniques/T1041/',
      'https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a'
    ],
    mitre: 'T1041'
  },
  intent_command_exfil: {
    id: 'MUADDIB-INTENT-002',
    name: 'Intent Command Output Exfiltration',
    severity: 'HIGH',
    confidence: 'medium',
    description: 'Coherence d\'intention: sortie de commande systeme combinee avec un sink reseau. Le code execute des commandes et transmet les resultats sur le reseau — reconnaissance ou exfiltration.',
    references: [
      'https://attack.mitre.org/techniques/T1059/',
      'https://attack.mitre.org/techniques/T1041/'
    ],
    mitre: 'T1059'
  },

  // GlassWorm detections (mars 2026)
  unicode_invisible_injection: {
    id: 'MUADDIB-OBF-003',
    name: 'Unicode Invisible Character Injection',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Caracteres Unicode invisibles detectes (zero-width, variation selectors). Technique GlassWorm: encodage de payload malveillant via variation selectors (U+FE00-FE0F, U+E0100-E01EF) invisible dans les editeurs.',
    references: [
      'https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode',
      'https://attack.mitre.org/techniques/T1027/'
    ],
    mitre: 'T1027'
  },
  unicode_variation_decoder: {
    id: 'MUADDIB-AST-053',
    name: 'Unicode Variation Selector Decoder',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Decodeur de payload Unicode via variation selectors (.codePointAt + 0xFE00/0xE0100). Signature GlassWorm: le code reconstruit un payload octet par octet a partir de caracteres invisibles.',
    references: [
      'https://www.koi.security/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace',
      'https://attack.mitre.org/techniques/T1140/'
    ],
    mitre: 'T1140'
  },
  blockchain_c2_resolution: {
    id: 'MUADDIB-AST-054',
    name: 'Blockchain C2 Resolution (Dead Drop)',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Import Solana/Web3 + appel API C2 (getSignaturesForAddress, getTransaction). Technique GlassWorm: la blockchain sert de dead drop resolver pour obtenir l\'adresse C2 via le champ memo des transactions.',
    references: [
      'https://www.sonatype.com/blog/hijacked-npm-packages-deliver-malware-via-solana-linked-to-glassworm',
      'https://attack.mitre.org/techniques/T1102/'
    ],
    mitre: 'T1102'
  },
  blockchain_rpc_endpoint: {
    id: 'MUADDIB-AST-055',
    name: 'Hardcoded Blockchain RPC Endpoint',
    severity: 'MEDIUM',
    confidence: 'medium',
    description: 'Endpoint RPC blockchain hardcode (Solana mainnet, Infura Ethereum). Dans un package non-crypto, indique un potentiel canal C2 via blockchain.',
    references: [
      'https://www.koi.security/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace',
      'https://attack.mitre.org/techniques/T1102/'
    ],
    mitre: 'T1102'
  },

  // Compound scoring rules (v2.9.2)
  // Injected by applyCompoundBoosts() when co-occurring threat types indicate unambiguous malice.
  crypto_staged_payload: {
    id: 'MUADDIB-COMPOUND-001',
    name: 'Steganographic Payload + Crypto Decryption',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Reference a un fichier binaire (.png/.jpg/.wasm) avec eval() combinee avec dechiffrement crypto (createDecipher). Chaine steganographique complete: payload cache dans un fichier binaire, dechiffre a runtime.',
    references: [
      'https://attack.mitre.org/techniques/T1140/',
      'https://attack.mitre.org/techniques/T1027/003/'
    ],
    mitre: 'T1140'
  },
  lifecycle_typosquat: {
    id: 'MUADDIB-COMPOUND-002',
    name: 'Lifecycle Hook on Typosquat Package',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Script lifecycle (preinstall/postinstall) sur un package avec nom similaire a un package populaire. Vecteur classique de dependency confusion: le code s\'execute automatiquement a l\'installation.',
    references: [
      'https://attack.mitre.org/techniques/T1195/002/',
      'https://snyk.io/blog/typosquatting-attacks/'
    ],
    mitre: 'T1195.002'
  },
  lifecycle_inline_exec: {
    id: 'MUADDIB-COMPOUND-004',
    name: 'Lifecycle Hook + Inline Node Execution',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Script lifecycle avec execution inline Node.js (node -e). Le code s\'execute automatiquement a npm install avec un payload inline.',
    references: [
      'https://attack.mitre.org/techniques/T1059/007/',
      'https://attack.mitre.org/techniques/T1195/002/'
    ],
    mitre: 'T1059.007'
  },
  lifecycle_remote_require: {
    id: 'MUADDIB-COMPOUND-005',
    name: 'Lifecycle Hook + Remote Code Loading',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Script lifecycle avec require(http/https) pour charger du code distant. Le payload est telecharge et execute automatiquement a l\'installation.',
    references: [
      'https://attack.mitre.org/techniques/T1105/',
      'https://attack.mitre.org/techniques/T1195/002/'
    ],
    mitre: 'T1105'
  },
};

function getRule(type) {
  if (RULES[type]) return RULES[type];
  if (PARANOID_RULES[type]) return PARANOID_RULES[type];
  if (PARANOID_RULES_BY_ID[type]) return PARANOID_RULES_BY_ID[type];
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

// Reverse-map: PARANOID rule ID → rule object (for scanParanoid threats)
const PARANOID_RULES_BY_ID = {};
for (const [, rule] of Object.entries(PARANOID_RULES)) {
  PARANOID_RULES_BY_ID[rule.id] = rule;
}

module.exports = { RULES, getRule, PARANOID_RULES };