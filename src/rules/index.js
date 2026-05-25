// =============================================================================
// Risk Domains taxonomy (P0a — inspired by Phylum's 5-domain model).
// Each rule SHOULD declare a `domain` field. Untagged rules default to
// 'malware' (the majority case). The 6 valid values are:
//
//  - malware       : explicit malicious code/behavior (eval+exfil, reverse
//                    shell, lifecycle hijack, IOC match, typosquat, etc.)
//  - author        : maintainer/author identity issues (unclaimed/compromised
//                    email domain, new publisher, deceptive author)
//  - engineering   : package quality / supply-chain hygiene (release_zero,
//                    version 99 dep-confusion, direct URL deps, missing repo)
//  - vulnerability : code-quality weaknesses that may not be intentional
//                    (eval usage, prototype pollution, dangerous APIs)
//  - license       : licensing conflicts (reserved — none currently)
//  - unknown       : fallback for unclassified threats
//
// Output exposure:
//  - SARIF: result.properties.risk_domain
//  - JSON : threat.domain field
//  - HTML : grouped section + colored badge per domain
//  - CLI  : [MAL]/[AUT]/[ENG]/[VUL]/[LIC] prefix
// =============================================================================

const RISK_DOMAINS = Object.freeze({
  MALWARE: 'malware',
  AUTHOR: 'author',
  ENGINEERING: 'engineering',
  VULNERABILITY: 'vulnerability',
  LICENSE: 'license',
  UNKNOWN: 'unknown'
});

const VALID_DOMAINS = new Set(Object.values(RISK_DOMAINS));

// 3-letter codes for compact CLI/output display (matches Phylum convention).
const DOMAIN_CODES = Object.freeze({
  malware: 'MAL',
  author: 'AUT',
  engineering: 'ENG',
  vulnerability: 'VUL',
  license: 'LIC',
  unknown: 'UNK'
});

const RULES = {
  // AST detections
  sensitive_string: {
    id: 'MUADDIB-AST-001',
    name: 'Sensitive String Reference',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'vulnerability',
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
    domain: 'vulnerability',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
    description: 'Script preinstall/postinstall suspect dans package.json',
    references: [
      'https://blog.npmjs.org/post/141577284765/kik-left-pad-and-npm'
    ],
    mitre: 'T1195.002'
  },
  monorepo_detected: {
    id: 'MUADDIB-PKG-021',
    name: 'Monorepo Detected',
    severity: 'MEDIUM',
    confidence: 'high',
    domain: 'malware',
    description: 'Workspace monorepo detecte (yarn/pnpm/lerna/turbo). Le perimetre du scan depasse un seul package — auditer chaque workspace separement pour un scoring per-package.',
    references: [
      'https://docs.npmjs.com/cli/v10/using-npm/workspaces'
    ],
    mitre: 'T1195.002'
  },

  // Obfuscation detections
  obfuscation_detected: {
    id: 'MUADDIB-OBF-001',
    name: 'Code Obfuscation Detected',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
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
    domain: 'malware',
    description: 'Package present dans la base IOC de packages malveillants connus',
    references: [
      'https://socket.dev/npm/issue'
    ],
    mitre: 'T1195.002'
  },
  dependency_ioc_match: {
    id: 'MUADDIB-DEP-006',
    name: 'Dependency Declared on IOC Package',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: 'Le package declare une dependance sur un package present dans la base IOC. Signal informatif — ne prouve pas que le package scanne est malveillant.',
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
    domain: 'malware',
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
    domain: 'malware',
    description: 'Dependance PyPI suspecte de typosquatting d\'un package populaire (Levenshtein)',
    references: [
      'https://pypi.org/',
      'https://blog.phylum.io/typosquatting-pypi'
    ],
    mitre: 'T1195.002'
  },

  // PYSRC-001 a 008 — Python source scanner (TrapDoor PyPI gap, v2.11.25).
  // python.js est manifest-only ; ast.js/dataflow.js sont JS-only ; ioc-strings.js
  // fait du literal match. Aucun ne couvre l'execution a l'import via __init__.py
  // / setup.py. Ces 8 regles ferment ce gap.
  import_time_exec: {
    id: 'MUADDIB-PYSRC-001',
    name: 'Python Import-Time exec/eval',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Fichier Python (__init__.py, setup.py, top-level *.py) contient exec()/eval() — execution directe de code a l\'import ou a pip install. RCE immediat sur la machine de l\'utilisateur. Pattern central de TrapDoor (mai 2026).',
    references: [
      'https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates',
      'https://attack.mitre.org/techniques/T1059/006/'
    ],
    mitre: 'T1059.006'
  },
  import_time_subprocess: {
    id: 'MUADDIB-PYSRC-002',
    name: 'Python Import-Time subprocess',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Fichier Python contient subprocess.Popen/run/call/check_output au niveau module — spawn d\'un processus externe a l\'import ou pip install. Utilise pour fetch + execute remote payload ou pour latteral movement.',
    references: [
      'https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates',
      'https://attack.mitre.org/techniques/T1059/006/'
    ],
    mitre: 'T1059.006'
  },
  import_time_os_system: {
    id: 'MUADDIB-PYSRC-003',
    name: 'Python Import-Time os.system / os.popen / os.spawn / os.exec',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Fichier Python contient os.system(), os.popen(), os.spawn*() ou os.exec*() au niveau module — shell execution a l\'import ou pip install. Generalement utilise pour curl|sh ou wget|bash remote payload.',
    references: [
      'https://attack.mitre.org/techniques/T1059/006/',
      'https://attack.mitre.org/techniques/T1059/004/'
    ],
    mitre: 'T1059.006'
  },
  import_time_fetch_exec: {
    id: 'MUADDIB-PYSRC-004',
    name: 'Python Import-Time Fetch + Exec (TrapDoor pattern)',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Compound detection : le meme fichier Python contient (urllib.request / requests / http.client / httpx / aiohttp) ET exec()/eval(). Signature directe de TrapDoor : telecharge un payload depuis le C2 et l\'execute. Implique RCE + capacite C2 active.',
    references: [
      'https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates',
      'https://attack.mitre.org/techniques/T1105/',
      'https://attack.mitre.org/techniques/T1059/006/'
    ],
    mitre: 'T1105'
  },
  import_time_base64_exec: {
    id: 'MUADDIB-PYSRC-005',
    name: 'Python Import-Time Base64 Decode + Exec',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Compound detection : le meme fichier Python contient base64.b64decode / codecs.decode ET exec()/eval(). Pattern d\'obfuscation classique : payload encode en base64 (parfois chaine multiple) puis execute. Vu dans Lazarus PyPI campaigns + TrapDoor.',
    references: [
      'https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates',
      'https://attack.mitre.org/techniques/T1027/',
      'https://attack.mitre.org/techniques/T1059/006/'
    ],
    mitre: 'T1027'
  },
  import_time_deserialization: {
    id: 'MUADDIB-PYSRC-006',
    name: 'Python Import-Time Unsafe Deserialization',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'vulnerability',
    description: 'Fichier Python utilise pickle/cPickle/marshal/dill/cloudpickle/jsonpickle/shelve .loads() au niveau module. Ces fonctions sont trivialement RCE si l\'input est attaquant-controle (deserialization = code execution). Risque critique meme sans malveillance prouvee.',
    references: [
      'https://docs.python.org/3/library/pickle.html#restricting-globals',
      'https://attack.mitre.org/techniques/T1059/006/',
      'https://cwe.mitre.org/data/definitions/502.html'
    ],
    mitre: 'T1059.006'
  },
  dynamic_dangerous_import: {
    id: 'MUADDIB-PYSRC-007',
    name: 'Python Dynamic __import__ of Dangerous Module',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: 'Fichier Python utilise __import__() avec un nom hardcode dangereux (subprocess, os, requests, urllib, socket, http, ssl, ctypes, importlib). Pattern d\'obfuscation : evite l\'instruction "import X" statique pour echapper aux scanners qui ne tracent que les imports declares.',
    references: [
      'https://attack.mitre.org/techniques/T1027/',
      'https://docs.python.org/3/library/functions.html#import__'
    ],
    mitre: 'T1027'
  },
  python_source_unicode_obfuscation: {
    id: 'MUADDIB-PYSRC-008',
    name: 'Python Source Unicode Obfuscation',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Fichier Python contient ≥5 caracteres Unicode invisibles (zero-width, directional override, variation selectors, tag characters). Mirror de AICONF-004 pour les sources .py. Python rejette les identifiers avec ZW chars (SyntaxError, PEP 3131), donc le vecteur principal c\'est l\'obfuscation dans les strings (GlassWorm-style payload encoding) ou dans les comments (mislead human review).',
    references: [
      'https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode',
      'https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates',
      'https://trojansource.codes/',
      'https://attack.mitre.org/techniques/T1027/'
    ],
    mitre: 'T1027.013'
  },
  // PYSRC-009 / 010 — fork-exec inline interpreter (v2.11.46). Comble le gap
  // TrapDoor exact : subprocess.run(["node"|"bash"|..., "-e"|"-c", payload]).
  // Pattern transversal multi-langage qui echappe a PYAST-005 parce qu'il n'y
  // a pas d'exec()/eval() Python — l'execution est cote interpreter forked.
  fork_exec_inline_interpreter: {
    id: 'MUADDIB-PYSRC-009',
    name: 'Python Fork-Exec Inline Interpreter',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'subprocess.{Popen,run,call,check_output,check_call,getoutput}([<interpreter>, <inline-flag>, ...]) — fork-exec d\'un interpreteur inline (node -e, python -c, bash -c, ruby -e, perl -e, php -r, ...). Signe canonique d\'un staging multi-langage : Python ouvre un autre interpreteur et lui passe du code dans argv. Pattern central de TrapDoor (mai 2026).',
    references: [
      'https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates',
      'https://attack.mitre.org/techniques/T1059/'
    ],
    mitre: 'T1059'
  },
  fetch_to_fork_exec_inline: {
    id: 'MUADDIB-PYSRC-010',
    name: 'Python Fetch + Fork-Exec Inline Interpreter (TrapDoor signature)',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Compound : le meme fichier Python contient un fetch reseau (urllib/requests/httpx/aiohttp/http.client) ET un subprocess.X([<interpreter>, -e|-c, ...]). Signature directe de TrapDoor : telecharge un payload depuis le C2 puis l\'execute via fork-exec d\'un interpreteur inline. Echappe a PYAST-005 (fetch+exec taint) parce que l\'execution est cote Node/Bash/Ruby/... pas cote Python.',
    references: [
      'https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates',
      'https://attack.mitre.org/techniques/T1105/',
      'https://attack.mitre.org/techniques/T1059/'
    ],
    mitre: 'T1105'
  },

  // PYAST-001 a 008 — Python AST scanner via tree-sitter (TrapDoor PyPI parity,
  // v2.11.42+). Mirror du `ast.js` cote npm : full CST walk avec scope tracking,
  // detecteurs scope-aware. Coexiste avec PYSRC-001..008 (regex) en defense
  // en profondeur — PYAST emet des findings plus precis (scope-aware), PYSRC
  // sert de fast-path.
  // IDs 005, 006, 009, 010 sont RESERVES pour Phase 1b (detecteurs taint-aware :
  // fetch->exec, base64->exec, ctypes shellcode, env->network).
  pyast_setup_cmdclass_override: {
    id: 'MUADDIB-PYAST-001',
    name: 'setup.py cmdclass Override',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'setup.py contient setup(cmdclass={...}) qui override une commande install-time (install / develop / build_ext / etc.). C\'est le vecteur #1 d\'install-time RCE sur PyPI : la classe custom override .run() pour executer du code arbitraire pendant pip install. Pattern central de TrapDoor (mai 2026) et de la plupart des Lazarus/SilentSync PyPI.',
    references: [
      'https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates',
      'https://securitylabs.datadoghq.com/articles/guarddog-identify-malicious-pypi-packages/',
      'https://attack.mitre.org/techniques/T1195/002/'
    ],
    mitre: 'T1195.002'
  },
  pyast_setup_entry_points_suspicious: {
    id: 'MUADDIB-PYAST-002',
    name: 'setup.py Suspicious Entry Points',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: 'setup.py declare console_scripts ou distutils.commands avec des noms suspects (commence par _, post_install, setup_, install_) — souvent utilise pour s\'executer apres install ou s\'enregistrer comme hook systeme. Heuristique : confidence medium (les entry_points legit sont la majorite).',
    references: [
      'https://docs.python.org/3/distutils/setupscript.html',
      'https://attack.mitre.org/techniques/T1546/'
    ],
    mitre: 'T1546'
  },
  pyast_module_level_exec: {
    id: 'MUADDIB-PYAST-003',
    name: 'Python Module-Level exec/eval (AST-confirmed)',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'AST-confirmed : exec()/eval() au niveau module (scope_depth == 0, hors function/class/lambda). S\'execute systematiquement a l\'import ou pip install. RCE direct. Plus precis que PYSRC-001 (regex) qui flag aussi exec dans des fonctions non-appelees.',
    references: [
      'https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates',
      'https://attack.mitre.org/techniques/T1059/006/'
    ],
    mitre: 'T1059.006'
  },
  pyast_module_level_subprocess_shell: {
    id: 'MUADDIB-PYAST-004',
    name: 'Python Module-Level subprocess shell=True (AST-confirmed)',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'AST-confirmed : subprocess.Popen/run/call/check_output/getoutput(..., shell=True) au niveau module. shell=True ouvre la porte a l\'injection de commande shell ; combine a une execution a l\'import, c\'est un vecteur direct de RCE. Equivalent Bandit B602.',
    references: [
      'https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html',
      'https://attack.mitre.org/techniques/T1059/006/'
    ],
    mitre: 'T1059.006'
  },
  pyast_module_level_unsafe_deserialization: {
    id: 'MUADDIB-PYAST-007',
    name: 'Python Module-Level Unsafe Deserialization (AST-confirmed)',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'vulnerability',
    description: 'AST-confirmed : pickle/cPickle/marshal/dill/cloudpickle/jsonpickle/shelve .loads()/.load() au niveau module. Ces fonctions sont trivialement RCE sur input attaquant-controle (CWE-502). Au niveau module ca s\'execute a l\'import. Equivalent Bandit B301.',
    references: [
      'https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b301-pickle',
      'https://docs.python.org/3/library/pickle.html#restricting-globals',
      'https://cwe.mitre.org/data/definitions/502.html'
    ],
    mitre: 'T1059.006'
  },
  pyast_dynamic_dangerous_import: {
    id: 'MUADDIB-PYAST-008',
    name: 'Python Dynamic __import__ of Dangerous Module (AST-confirmed)',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'AST-confirmed : __import__() avec un nom hardcode dangereux (subprocess, os, requests, urllib, socket, http, ssl, ctypes, importlib). Pattern d\'obfuscation pour eviter "import X" statique et echapper aux scanners qui tracent uniquement les declarations d\'import. Plus precis que PYSRC-007 (regex) — confirme via AST que c\'est bien un appel a __import__ et pas une mention dans une string ou un commentaire.',
    references: [
      'https://docs.python.org/3/library/functions.html#import__',
      'https://attack.mitre.org/techniques/T1027/'
    ],
    mitre: 'T1027'
  },

  // PYAST-005, 006, 009, 010 — Phase 1b (v2.11.45) : detecteurs taint-aware
  // qui utilisent ctx.moduleTaint populee par handle-assignment.js.
  // Mini-taint intra-procedural mono-fichier, single-hop. Voir python-ast-detectors/
  // taint-tracker.js pour les sources + le plan Phase 1b pour les limitations.
  pyast_fetch_to_exec_taint: {
    id: 'MUADDIB-PYAST-005',
    name: 'Python Fetch + Exec Taint (TrapDoor compound)',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Compound taint-aware : variable assignee depuis un fetch reseau (urllib / requests / httpx / aiohttp / http.client) puis passee a exec()/eval() au niveau module. Signature directe de remote-payload-then-RCE — pattern TrapDoor mai 2026 et Lazarus PyPI series.',
    references: [
      'https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates',
      'https://attack.mitre.org/techniques/T1105/',
      'https://attack.mitre.org/techniques/T1059/006/'
    ],
    mitre: 'T1105'
  },
  pyast_base64_to_exec_taint: {
    id: 'MUADDIB-PYAST-006',
    name: 'Python Base64/Decode + Exec Taint (Obfuscated Payload)',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Compound taint-aware : variable assignee depuis un decode (base64 / codecs / zlib / gzip / binascii / bytes.fromhex) puis passee a exec()/eval() au niveau module. Pattern d\'obfuscation pour echapper a la revue + grep statique. Vu dans W4SP / Crystal / Lumma stealers PyPI.',
    references: [
      'https://attack.mitre.org/techniques/T1027/',
      'https://attack.mitre.org/techniques/T1059/006/'
    ],
    mitre: 'T1027'
  },
  pyast_ctypes_shellcode_load: {
    id: 'MUADDIB-PYAST-009',
    name: 'Python ctypes Shellcode Loader',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: 'ctypes.CDLL / WinDLL / LoadLibrary appele avec (a) un path suspect (/tmp, /var/tmp, /dev/shm, ~/, C:\\Windows\\Temp\\, ...) ou (b) un argument taintee venant d\'un fetch ou d\'un decode. Pattern de loader de shellcode native (.so / .dll dropped sur disque puis charge en memoire). Vu dans les campagnes RATs Python.',
    references: [
      'https://docs.python.org/3/library/ctypes.html',
      'https://attack.mitre.org/techniques/T1055/'
    ],
    mitre: 'T1055'
  },
  pyast_env_to_network_write: {
    id: 'MUADDIB-PYAST-010',
    name: 'Python Env Read + Network POST Taint (Credential Exfil)',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Compound taint-aware : variable assignee depuis os.environ[X] / os.environ.get(X) / os.getenv(X) puis envoyee dans le body d\'une requete POST/PUT/PATCH (requests / httpx / urllib.Request). Pattern d\'exfiltration de credentials. Severity escaladee a CRITICAL si le nom de la variable d\'env match un pattern sensible (TOKEN, KEY, SECRET, PASSWORD, NPM_, AWS_, SSH, API, GITHUB_, HF_, ANTHROPIC, ...).',
    references: [
      'https://attack.mitre.org/techniques/T1041/',
      'https://attack.mitre.org/techniques/T1552/001/'
    ],
    mitre: 'T1041'
  },

  suspicious_file: {
    id: 'MUADDIB-DEP-002',
    name: 'Suspicious File in Dependency',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
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
    domain: 'malware',
    description: 'Marqueur Shai-Hulud detecte dans le code',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm',
      'https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack'
    ],
    mitre: 'T1195.002'
  },
  ioc_string_match: {
    id: 'MUADDIB-IOC-001',
    name: 'YARA-style String IOC Match',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Literal substring uniquement attribuable a une campagne malware connue (XOR key, RAT command name, C2 path, build artifact). Le match en source = signal CRITICAL transverse a toutes les variantes qui reuse le meme stager.',
    references: [
      'iocs/string-iocs.yaml',
      'https://gist.github.com/N3mes1s/0c0fc7a0c23cdb5e1c8f66b208053ed6',
      'https://unit42.paloaltonetworks.com/axios-supply-chain-attack/',
      'https://blog.gitguardian.com/three-supply-chain-campaigns-hit-npm-pypi-and-docker-hub-in-48-hours/'
    ],
    mitre: 'T1195.002'
  },
  anti_forensic_xor_autodelete: {
    id: 'MUADDIB-AF-001',
    name: 'Anti-Forensic XOR + Self-Delete + Decoy Write',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Compound AST pattern: XOR loop with literal-derived operand + fs.unlink/rename of self file + fs.writeFile to a decoy extension (.md/.bak/.tmp/.txt/.log) all in the same source file. Catches the Axios npm 2026-03 setup.js dropper and the csec autodelete family even when the XOR key string is rotated.',
    references: [
      'https://gist.github.com/N3mes1s/0c0fc7a0c23cdb5e1c8f66b208053ed6',
      'https://unit42.paloaltonetworks.com/axios-supply-chain-attack/'
    ],
    mitre: 'T1140'
  },
  anti_forensic_partial: {
    id: 'MUADDIB-AF-002',
    name: 'Anti-Forensic Partial (2 of 3 patterns)',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: '2 of 3 anti-forensic patterns in a single file (XOR loop, self-delete, decoy write). Insufficient for CRITICAL alone but elevates a package that already shows other signals.',
    references: [
      'https://gist.github.com/N3mes1s/0c0fc7a0c23cdb5e1c8f66b208053ed6'
    ],
    mitre: 'T1140'
  },
  stub_package_external_payload: {
    id: 'MUADDIB-STUB-001',
    name: 'Stub Package + External URL Dep + Lifecycle Hook',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Package main file is essentially empty AND declares a non-npm-registry URL dependency AND has an install lifecycle hook. The malicious payload lives in the resolved external dep, not the published tarball. Closes the ltidi chain attack class that bypassed ADR_THRESHOLD=20.',
    references: [
      'project_detection_gap_ltidi_chain memory entry',
      'https://blog.gitguardian.com/three-supply-chain-campaigns-hit-npm-pypi-and-docker-hub-in-48-hours/'
    ],
    mitre: 'T1195.002'
  },
  stub_package_external_dep: {
    id: 'MUADDIB-STUB-002',
    name: 'Stub Package + External URL Dep (no lifecycle)',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: 'Package main file is essentially empty AND declares a non-npm-registry URL dependency. No lifecycle hook so the payload requires an explicit require() — manual review still warranted because legitimate libs that pull a payload via URL would re-export the dep.',
    references: [
      'project_detection_gap_ltidi_chain memory entry'
    ],
    mitre: 'T1195.002'
  },
  axios_family: {
    id: 'MUADDIB-COMPOUND-AXIOS',
    name: 'Axios / csec Family Compound',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Compound: IOC string match + lifecycle hook + anti-forensic partial pattern. Identifies the BlueNoroff/Sapphire Sleet Axios family and the csec autodelete family at a single glance.',
    references: [
      'https://gist.github.com/N3mes1s/0c0fc7a0c23cdb5e1c8f66b208053ed6',
      'https://unit42.paloaltonetworks.com/axios-supply-chain-attack/'
    ],
    mitre: 'T1195.002'
  },
  stub_with_string_ioc: {
    id: 'MUADDIB-COMPOUND-STUB-IOC',
    name: 'Stub Package + Known String IOC',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Compound: stub package (small main, external URL dep) AND a known string IOC in source. Unambiguous chain-attack staging.',
    references: [
      'project_detection_gap_ltidi_chain memory entry'
    ],
    mitre: 'T1195.002'
  },
  staged_remote_loader: {
    id: 'MUADDIB-COMPOUND-012',
    name: 'Staged Remote Loader (Function.constructor + shadowed process)',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Compound: new Function.constructor("require", body) co-occurs with `const process = {...}` shadowing in the same file. Pattern observed in the chai-* / poxios-chain / express-guardrail / justenv campaign (semaine 2026-05-04 a 2026-05-09): fork de pino avec caller.js qui decode une URL base64 (jsonkeeper.com), fetch le payload distant via axios, et l\'execute via Function.constructor en passant require comme parametre. Le tarball npm ne contient aucun code malveillant statique — la charge utile est externalisee sur un pastebin.',
    references: [
      'project_detection_gap_chai_staged_loader memory entry',
      'data/security-review-2026-05-04-10.md'
    ],
    mitre: 'T1059.007'
  },
  lifecycle_script_dependency: {
    id: 'MUADDIB-DEP-004',
    name: 'Lifecycle Script in Dependency',
    severity: 'MEDIUM',
    confidence: 'low',
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
    description: 'Package avec un nom tres similaire a un package populaire. Possible typosquatting.',
    references: [
      'https://blog.npmjs.org/post/163723642530/crossenv-malware-on-the-npm-registry',
      'https://snyk.io/blog/typosquatting-attacks/'
    ],
    mitre: 'T1195.002'
  },

  // RT-C1: Dependency boundary-squat (Axios UNC1069 March 2026)
  dependency_typosquat: {
    id: 'MUADDIB-TYPO-002',
    name: 'Dependency Boundary-Squat',
    // RT-C1-FPR (audit 2026-05): demoted HIGH -> MEDIUM. Boundary-squat alone is
    // a name-resemblance heuristic without execution proof. Compounds typosquat_lifecycle
    // (CRITICAL), typosquat_dataflow (HIGH), dependency_typosquat_require (CRITICAL)
    // escalate when co-occurring with real execution/exfil signals.
    severity: 'MEDIUM',
    confidence: 'high',
    domain: 'malware',
    description: 'Une dependance declaree porte le nom d\'un package populaire prefixe/suffixe d\'un token suspect (Axios UNC1069, mars 2026). Le wrapper innocent declare un sub-dep malveillant. Signal solo MEDIUM, escalade CRITICAL via compounds lifecycle/dataflow/require.',
    references: [
      'https://snyk.io/blog/typosquatting-attacks/',
      'https://attack.mitre.org/techniques/T1195/002/'
    ],
    mitre: 'T1195.002'
  },
  dependency_typosquat_used: {
    id: 'MUADDIB-TYPO-003',
    name: 'Boundary-Squat Dependency Used in Code',
    severity: 'MEDIUM',
    confidence: 'high',
    domain: 'malware',
    description: 'Le code du package require/import un nom de dependance identifie comme boundary-squat. Signal fort que la dep typosquattee est intentionnellement chargee.',
    references: ['https://attack.mitre.org/techniques/T1195/002/'],
    mitre: 'T1195.002'
  },
  dependency_typosquat_require: {
    id: 'MUADDIB-COMPOUND-013',
    name: 'Boundary-Squat Dep Required at Runtime',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Dependance boundary-squat declaree ET chargee via require/import dans le code: pattern Axios UNC1069 (sub-dep injection avec wrapper innocent).',
    references: ['https://attack.mitre.org/techniques/T1195/002/'],
    mitre: 'T1195.002'
  },
  // RT-C1-FPR (audit 2026-05): compounds escaladant dependency_typosquat solo (MEDIUM)
  typosquat_lifecycle: {
    id: 'MUADDIB-COMPOUND-014',
    name: 'Boundary-Squat Dep + Lifecycle Hook',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Dependance boundary-squat declaree avec script lifecycle (preinstall/postinstall) — install-time payload delivery via typosquat sub-dep.',
    references: ['https://attack.mitre.org/techniques/T1195/002/'],
    mitre: 'T1195.002'
  },
  typosquat_dataflow: {
    id: 'MUADDIB-COMPOUND-015',
    name: 'Boundary-Squat Dep + Suspicious Dataflow',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Dependance boundary-squat declaree avec flux de donnees suspect (lecture credentials + envoi reseau) — typosquat dep co-occurring with exfiltration.',
    references: ['https://attack.mitre.org/techniques/T1195/002/'],
    mitre: 'T1195.002'
  },

  // Package.json script patterns
  curl_pipe_sh: {
    id: 'MUADDIB-PKG-002',
    name: 'Curl Pipe to Shell in Script',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Script lifecycle execute curl | sh - telechargement et execution de code distant',
    references: ['https://blog.phylum.io/shai-hulud-npm-worm'],
    mitre: 'T1105'
  },
  wget_pipe_sh: {
    id: 'MUADDIB-PKG-003',
    name: 'Wget Pipe to Shell in Script',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Script lifecycle execute wget | sh - telechargement et execution de code distant',
    references: ['https://blog.phylum.io/shai-hulud-npm-worm'],
    mitre: 'T1105'
  },
  eval_usage: {
    id: 'MUADDIB-PKG-004',
    name: 'Eval in Lifecycle Script',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: 'Utilisation de eval() dans un script lifecycle - execution de code dynamique',
    references: ['https://owasp.org/www-community/attacks/Command_Injection'],
    mitre: 'T1059.007'
  },
  child_process: {
    id: 'MUADDIB-PKG-005',
    name: 'Child Process in Lifecycle Script',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: 'Reference a child_process dans un script lifecycle',
    references: ['https://owasp.org/www-community/attacks/Command_Injection'],
    mitre: 'T1059'
  },
  npmrc_access: {
    id: 'MUADDIB-PKG-006',
    name: 'npmrc Access',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Acces au fichier .npmrc detecte - risque de vol de token npm',
    references: ['https://blog.phylum.io/shai-hulud-npm-worm'],
    mitre: 'T1552.001'
  },
  github_token_access: {
    id: 'MUADDIB-PKG-007',
    name: 'GitHub Token Access',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Acces au GITHUB_TOKEN detecte',
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions'],
    mitre: 'T1552.001'
  },
  aws_credential_access: {
    id: 'MUADDIB-PKG-008',
    name: 'AWS Credential Access',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Acces aux credentials AWS detecte',
    references: ['https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html'],
    mitre: 'T1552.001'
  },
  base64_encoding: {
    id: 'MUADDIB-PKG-009',
    name: 'Base64 Encoding in Script',
    severity: 'MEDIUM',
    confidence: 'low',
    domain: 'malware',
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
    domain: 'malware',
    description: 'Telechargement et execution via curl | sh dans un script shell',
    references: ['https://blog.phylum.io/shai-hulud-npm-worm'],
    mitre: 'T1105'
  },
  wget_chmod_exec: {
    id: 'MUADDIB-SHELL-005',
    name: 'Wget Download and Execute',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Telechargement et execution de binaire via wget + chmod',
    references: ['https://blog.phylum.io/shai-hulud-npm-worm'],
    mitre: 'T1105'
  },
  netcat_shell: {
    id: 'MUADDIB-SHELL-006',
    name: 'Netcat Shell',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Shell netcat detecte - acces distant non autorise',
    references: ['https://attack.mitre.org/techniques/T1059/004/'],
    mitre: 'T1059.004'
  },
  shred_home: {
    id: 'MUADDIB-SHELL-007',
    name: 'Home Directory Destruction',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Destruction de donnees (shred $HOME) - dead man\'s switch de Shai-Hulud',
    references: ['https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack'],
    mitre: 'T1485'
  },
  curl_exfiltration: {
    id: 'MUADDIB-SHELL-008',
    name: 'Data Exfiltration via Curl',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Exfiltration de donnees via curl POST',
    references: ['https://attack.mitre.org/techniques/T1041/'],
    mitre: 'T1041'
  },
  ssh_access: {
    id: 'MUADDIB-SHELL-009',
    name: 'SSH Key Access',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Acces aux cles SSH detecte',
    references: ['https://attack.mitre.org/techniques/T1552/004/'],
    mitre: 'T1552.004'
  },
  python_reverse_shell: {
    id: 'MUADDIB-SHELL-010',
    name: 'Python Reverse Shell',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Reverse shell via python -c import socket detecte',
    references: ['https://attack.mitre.org/techniques/T1059/004/'],
    mitre: 'T1059.006'
  },
  perl_reverse_shell: {
    id: 'MUADDIB-SHELL-011',
    name: 'Perl Reverse Shell',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Reverse shell via perl -e socket detecte',
    references: ['https://attack.mitre.org/techniques/T1059/004/'],
    mitre: 'T1059.006'
  },
  fifo_reverse_shell: {
    id: 'MUADDIB-SHELL-012',
    name: 'FIFO Reverse Shell',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Reverse shell via mkfifo /dev/tcp detecte',
    references: ['https://attack.mitre.org/techniques/T1059/004/'],
    mitre: 'T1059.004'
  },
  fifo_nc_reverse_shell: {
    id: 'MUADDIB-SHELL-013',
    name: 'FIFO + Netcat Reverse Shell',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Reverse shell via mkfifo + netcat (sans /dev/tcp). Technique alternative de reverse shell utilisant un named pipe.',
    references: ['https://attack.mitre.org/techniques/T1059/004/'],
    mitre: 'T1059.004'
  },
  base64_decode_exec: {
    id: 'MUADDIB-SHELL-014',
    name: 'Base64 Decode Pipe to Shell',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Payload encode en base64 decode et pipe vers bash/sh. Technique d\'obfuscation courante pour cacher des commandes malveillantes.',
    references: ['https://attack.mitre.org/techniques/T1140/'],
    mitre: 'T1140'
  },
  wget_base64_decode: {
    id: 'MUADDIB-SHELL-015',
    name: 'Wget + Base64 Decode',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
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
    domain: 'malware',
    description: 'Fichier potentiellement obfusque (parse echoue, code dense)',
    references: ['https://attack.mitre.org/techniques/T1027/'],
    mitre: 'T1027'
  },
  dynamic_require: {
    id: 'MUADDIB-AST-006',
    name: 'Dynamic Require with Concatenation',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'require() avec concatenation de chaines — technique d\'obfuscation pour masquer le nom du module',
    references: ['https://attack.mitre.org/techniques/T1027/'],
    mitre: 'T1027'
  },
  dangerous_exec: {
    id: 'MUADDIB-AST-007',
    name: 'Dangerous Shell Command Execution',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'exec() avec commande shell dangereuse (pipe to shell, reverse shell, netcat)',
    references: ['https://owasp.org/www-community/attacks/Command_Injection'],
    mitre: 'T1059.004'
  },
  staged_payload: {
    id: 'MUADDIB-FLOW-002',
    name: 'Staged Payload Execution',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Telechargement reseau + eval() dans le meme fichier — execution de payload distant',
    references: ['https://attack.mitre.org/techniques/T1105/'],
    mitre: 'T1105'
  },
  network_require: {
    id: 'MUADDIB-PKG-011',
    name: 'Network Module in Lifecycle Script',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'require(https/http) dans un script lifecycle — telechargement au moment de l\'installation',
    references: ['https://blog.phylum.io/shai-hulud-npm-worm'],
    mitre: 'T1105'
  },
  node_inline_exec: {
    id: 'MUADDIB-PKG-012',
    name: 'Node Inline Execution in Lifecycle Script',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'node -e dans un script lifecycle — execution de code inline au moment de l\'installation',
    references: ['https://owasp.org/www-community/attacks/Command_Injection'],
    mitre: 'T1059.007'
  },
  dynamic_import: {
    id: 'MUADDIB-AST-008',
    name: 'Dynamic import() of Dangerous Module',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'import() dynamique pour charger un module dangereux ou avec argument calcule — technique d\'evasion pour eviter la detection de require()',
    references: ['https://attack.mitre.org/techniques/T1027/'],
    mitre: 'T1027'
  },
  env_proxy_intercept: {
    id: 'MUADDIB-AST-009',
    name: 'Environment Variable Proxy Interception',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'new Proxy(process.env) detecte — intercepte silencieusement tous les acces aux variables d\'environnement pour exfiltration',
    references: ['https://attack.mitre.org/techniques/T1552/001/'],
    mitre: 'T1552.001'
  },
  dynamic_require_exec: {
    id: 'MUADDIB-AST-010',
    name: 'Command Execution via Dynamic Require',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'exec/execSync appele sur un module charge dynamiquement (require obfusque) — execution de commandes dissimulees',
    references: ['https://attack.mitre.org/techniques/T1059/007/'],
    mitre: 'T1059.007'
  },
  sandbox_evasion: {
    id: 'MUADDIB-AST-011',
    name: 'Sandbox/Container Evasion',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Detection de sandbox/container (/.dockerenv, /proc/cgroup) — technique anti-analyse pour eviter la detection en environnement controle',
    references: ['https://attack.mitre.org/techniques/T1497/001/'],
    mitre: 'T1497.001'
  },
  detached_process: {
    id: 'MUADDIB-AST-012',
    name: 'Detached Background Process',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'spawn/fork avec {detached: true} — le processus survit a la fin de npm install et execute le payload en arriere-plan',
    references: ['https://attack.mitre.org/techniques/T1036/009/'],
    mitre: 'T1036.009'
  },
  silent_stealth_process: {
    id: 'MUADDIB-AST-092',
    name: 'Silent Stealth Background Process',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'spawn/fork avec {detached: true, stdio: \'ignore\'} — combinaison qui detache le processus ET silence tous ses I/O. Signal de stealth specifique aux payloads installes via lifecycle (Shai-Hulud) qui doivent survivre a npm install sans laisser de trace dans les logs.',
    references: [
      'https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/sourcecode/npm-silent-process-execution.yml',
      'https://attack.mitre.org/techniques/T1036/009/',
      'https://attack.mitre.org/techniques/T1564/'
    ],
    mitre: 'T1564'
  },
  dangerous_call_function: {
    id: 'MUADDIB-AST-005',
    name: 'new Function() Constructor',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'vulnerability',
    description: 'Appel new Function() detecte - equivalent a eval()',
    references: ['https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/Function'],
    mitre: 'T1059.007'
  },

  credential_command_exec: {
    id: 'MUADDIB-AST-014',
    name: 'Credential Theft via CLI Tool',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
    description: 'Fichier de configuration d\'agent IA contient des commandes d\'exfiltration (curl POST vers un domaine externe, pipe vers shell) ou une combinaison commande shell + acces credentials. Attaque confirmee.',
    references: [
      'https://snyk.io/blog/toxicskills-prompt-injection-ai-agents/',
      'https://snyk.io/blog/clinejection-ai-config-prompt-injection/',
      'https://arxiv.org/abs/2601.17548',
      'https://developer.nvidia.com/blog/ai-agent-security-guidance/'
    ],
    mitre: 'T1059'
  },
  ide_hook_autoexec: {
    id: 'MUADDIB-AICONF-003',
    name: 'IDE Hook Auto-Execution',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Fichier de configuration IDE (.claude/settings.json, .vscode/tasks.json, .kiro/settings/mcp.json) contient des hooks qui executent du code automatiquement a l\'ouverture du projet. Technique Shai-Hulud (TeamPCP, mai 2026).',
    references: [
      'https://github.com/g00dfe11ow/Shai-Hulud-Open-Source',
      'https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm'
    ],
    mitre: 'T1546'
  },
  aiconf_unicode_obfuscation: {
    id: 'MUADDIB-AICONF-004',
    name: 'Zero-Width Unicode Obfuscation in AI Config',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Fichier de configuration d\'agent IA (.cursorrules, CLAUDE.md, copilot-instructions.md) contient des caracteres Unicode invisibles (zero-width, directional override, variation selectors) qui cachent des instructions a la revue humaine ou cassent des mots-cles pour echapper a la detection regex. Technique TrapDoor (mai 2026): cu​rl|sh interspersee de U+200B passe au travers du regex /curl/ tandis que l\'agent IA execute le payload normalise.',
    references: [
      'https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates',
      'https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode',
      'https://trojansource.codes/',
      'https://attack.mitre.org/techniques/T1027/'
    ],
    mitre: 'T1027.013'
  },

  require_cache_poison: {
    id: 'MUADDIB-AST-019',
    name: 'Require Cache Poisoning',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
    description: 'Backdoor Shai-Hulud dans GitHub Actions via workflow discussion.yaml sur self-hosted runner',
    references: ['https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack'],
    mitre: 'T1195.002'
  },
  workflow_injection: {
    id: 'MUADDIB-GHA-002',
    name: 'GitHub Actions Workflow Injection',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Injection potentielle dans GitHub Actions via input non sanitise sur self-hosted runner',
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions'],
    mitre: 'T1195.002'
  },
  workflow_pwn_request: {
    id: 'MUADDIB-GHA-003',
    name: 'GitHub Actions Pwn Request',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Workflow pull_request_target avec checkout du head ref/sha de la PR — permet execution de code arbitraire (pwn request)',
    references: [
      'https://securitylab.github.com/research/github-actions-preventing-pwn-requests/',
      'https://attack.mitre.org/techniques/T1195/002/'
    ],
    mitre: 'T1195.002'
  },
  workflow_secrets_dump: {
    id: 'MUADDIB-GHA-004',
    name: 'GitHub Actions Secrets Dump',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Workflow utilise toJSON(secrets) pour exfiltrer tous les secrets du repository. Technique Shai-Hulud (TeamPCP, mai 2026).',
    references: [
      'https://github.com/g00dfe11ow/Shai-Hulud-Open-Source',
      'https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions'
    ],
    mitre: 'T1552.001'
  },

  // Sandbox detections
  sandbox_sensitive_file_read: {
    id: 'MUADDIB-SANDBOX-001',
    name: 'Sandbox: Sensitive File Read',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Package reads sensitive credential files during install',
    references: ['https://blog.phylum.io/shai-hulud-npm-worm'],
    mitre: 'T1552.001'
  },
  sandbox_sensitive_file_write: {
    id: 'MUADDIB-SANDBOX-002',
    name: 'Sandbox: Sensitive File Write',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Package writes to sensitive credential files during install',
    references: ['https://blog.phylum.io/shai-hulud-npm-worm'],
    mitre: 'T1565.001'
  },
  sandbox_suspicious_filesystem: {
    id: 'MUADDIB-SANDBOX-003',
    name: 'Sandbox: Suspicious Filesystem Change',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Package creates files in suspicious system locations during install',
    references: ['https://attack.mitre.org/techniques/T1543/'],
    mitre: 'T1543'
  },
  sandbox_suspicious_dns: {
    id: 'MUADDIB-SANDBOX-004',
    name: 'Sandbox: Suspicious DNS Query',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: 'Package resolves non-registry domain during install',
    references: ['https://attack.mitre.org/techniques/T1071/'],
    mitre: 'T1071'
  },
  sandbox_suspicious_connection: {
    id: 'MUADDIB-SANDBOX-005',
    name: 'Sandbox: Suspicious Network Connection',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: 'Package makes TCP connection to non-registry host during install',
    references: ['https://attack.mitre.org/techniques/T1071/'],
    mitre: 'T1071'
  },
  sandbox_suspicious_process: {
    id: 'MUADDIB-SANDBOX-006',
    name: 'Sandbox: Dangerous Process Spawned',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Package spawns dangerous command during install (curl, wget, nc, etc.)',
    references: ['https://attack.mitre.org/techniques/T1059/'],
    mitre: 'T1059'
  },
  sandbox_unknown_process: {
    id: 'MUADDIB-SANDBOX-007',
    name: 'Sandbox: Unknown Process Spawned',
    severity: 'MEDIUM',
    confidence: 'low',
    domain: 'malware',
    description: 'Package spawns unrecognized process during install',
    references: ['https://attack.mitre.org/techniques/T1059/'],
    mitre: 'T1059'
  },
  sandbox_timeout: {
    id: 'MUADDIB-SANDBOX-008',
    name: 'Sandbox: Container Timeout',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
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
    domain: 'malware',
    description: 'Package uses setTimeout/setInterval with delay > 1 hour. Possible time-bomb to evade sandbox analysis.',
    references: ['https://attack.mitre.org/techniques/T1497/003/'],
    mitre: 'T1497.003'
  },
  sandbox_timer_delay_critical: {
    id: 'MUADDIB-SANDBOX-010',
    name: 'Sandbox: Critical Timer Delay (Time-Bomb)',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Package uses setTimeout/setInterval with delay > 24 hours. Strong indicator of time-bomb malware designed to evade sandbox analysis.',
    references: ['https://attack.mitre.org/techniques/T1497/003/'],
    mitre: 'T1497.003'
  },
  sandbox_preload_sensitive_read: {
    id: 'MUADDIB-SANDBOX-011',
    name: 'Sandbox: Preload Sensitive File Read',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Package reads sensitive credential files (.npmrc, .ssh, .aws, .env) detected via runtime monkey-patching.',
    references: ['https://attack.mitre.org/techniques/T1552/001/'],
    mitre: 'T1552.001'
  },
  sandbox_network_after_sensitive_read: {
    id: 'MUADDIB-SANDBOX-012',
    name: 'Sandbox: Network After Sensitive Read',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Package makes network requests after reading sensitive files. Strong indicator of credential exfiltration.',
    references: ['https://attack.mitre.org/techniques/T1041/'],
    mitre: 'T1041'
  },
  sandbox_exec_suspicious: {
    id: 'MUADDIB-SANDBOX-013',
    name: 'Sandbox: Suspicious Command Execution',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Package executes dangerous commands (curl, wget, bash, sh, powershell) detected via runtime monkey-patching.',
    references: ['https://attack.mitre.org/techniques/T1059/'],
    mitre: 'T1059'
  },
  sandbox_env_token_access: {
    id: 'MUADDIB-SANDBOX-014',
    name: 'Sandbox: Sensitive Env Var Access',
    severity: 'MEDIUM',
    confidence: 'medium',
    domain: 'malware',
    description: 'Package accesses sensitive environment variables (TOKEN, SECRET, KEY, PASSWORD) detected via runtime monkey-patching.',
    references: ['https://attack.mitre.org/techniques/T1552/001/'],
    mitre: 'T1552.001'
  },

  // Sandbox network outlier detections
  sandbox_network_outlier: {
    id: 'MUADDIB-SANDBOX-015',
    name: 'Sandbox: Network Outlier',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: 'Package contacts a non-registry domain/IP during install. Only 0.027% of packages make DNS queries outside npm infrastructure — this is a high-precision outlier signal.',
    references: ['https://attack.mitre.org/techniques/T1071/001/'],
    mitre: 'T1071.001'
  },
  sandbox_known_exfil_domain: {
    id: 'MUADDIB-SANDBOX-016',
    name: 'Sandbox: Known Exfiltration Domain',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Package contacts a known exfiltration/C2 domain during install (OAST, webhook sinks, campaign infrastructure). Near-zero false positive rate.',
    references: [
      'https://attack.mitre.org/techniques/T1041/',
      'https://attack.mitre.org/techniques/T1071/001/'
    ],
    mitre: 'T1041'
  },

  // Honey-trap and 2026 supply chain runtime signals
  sandbox_honey_read: {
    id: 'MUADDIB-SANDBOX-017',
    name: 'Sandbox: Honeypot Decoy File Read',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Le package lit un fichier decoy de credentials plante par la sandbox (.npmrc-decoy, .ssh/id_rsa-decoy, wallet decoy, etc.). Aucun outil legitime ne lit ces chemins. Capture les zero-days qui scannent aveuglement les chemins de credentials connus.',
    references: [
      'https://attack.mitre.org/techniques/T1552/001/',
      'https://blog.phylum.io/shai-hulud-npm-worm'
    ],
    mitre: 'T1552.001'
  },
  sandbox_credential_target_read: {
    id: 'MUADDIB-SANDBOX-018',
    name: 'Sandbox: Credential Target File Read',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Le package lit un fichier de credentials cible des malwares 2026 (cloud creds, wallets, browser data, GPG, kubernetes config). Pattern PhantomRaven, Shai-Hulud.',
    references: [
      'https://attack.mitre.org/techniques/T1552/001/',
      'https://attack.mitre.org/techniques/T1555/'
    ],
    mitre: 'T1555'
  },
  sandbox_persistence_write: {
    id: 'MUADDIB-SANDBOX-019',
    name: 'Sandbox: Persistence File Write',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Le package ecrit dans un emplacement de persistance (.bashrc, .zshrc, autostart, cron, systemd user, LaunchAgents, registry Run keys). Aucun cas legitime en npm install.',
    references: [
      'https://attack.mitre.org/techniques/T1547/',
      'https://attack.mitre.org/techniques/T1546/004/'
    ],
    mitre: 'T1547'
  },
  sandbox_execve_chain_depth: {
    id: 'MUADDIB-SANDBOX-020',
    name: 'Sandbox: Suspicious Execve Chain Depth',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: 'Chaine de processus depuis npm install au-dela de la profondeur attendue (npm install -> script -> binaire externe). Pattern Shai-Hulud preinstall worm avec curl/wget/bash final.',
    references: [
      'https://unit42.paloaltonetworks.com/npm-supply-chain-attack/',
      'https://attack.mitre.org/techniques/T1059/'
    ],
    mitre: 'T1059'
  },
  sandbox_npm_self_invoke: {
    id: 'MUADDIB-SANDBOX-021',
    name: 'Sandbox: npm CLI Self-Invocation',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Le package invoque npm publish/deprecate/owner/token/access (ou yarn publish) depuis l\'arborescence npm install. Pattern CanisterWorm self-propagation. Aucun cas legitime.',
    references: [
      'https://www.stepsecurity.io/blog/canisterworm-how-a-self-propagating-npm-worm-is-spreading-backdoors-across-the-ecosystem/',
      'https://attack.mitre.org/techniques/T1195.002/'
    ],
    mitre: 'T1195.002'
  },
  sandbox_runtime_deobfuscation_executed: {
    id: 'MUADDIB-SANDBOX-022',
    name: 'Sandbox: Runtime Deobfuscation Executed',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'new Function() ou eval() execute avec un body de plus de 500 octets, derive d\'une string source obfusquee (high entropy ou taille >1KB). Pattern Axios 2026 OrDeR_7077: XOR + base64 decoded at runtime then executed.',
    references: [
      'https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/',
      'https://attack.mitre.org/techniques/T1027/',
      'https://attack.mitre.org/techniques/T1059.007/'
    ],
    mitre: 'T1027'
  },

  // Entropy detections
  high_entropy_string: {
    id: 'MUADDIB-ENTROPY-001',
    name: 'High Entropy String',
    severity: 'MEDIUM',
    confidence: 'medium',
    domain: 'malware',
    description: 'Chaine a haute entropie detectee (base64, hex, payload chiffre). Souvent signe d\'obfuscation ou de donnees encodees.',
    references: ['https://attack.mitre.org/techniques/T1027/'],
    mitre: 'T1027'
  },
  fragmented_high_entropy_cluster: {
    id: 'MUADDIB-ENTROPY-004',
    name: 'Fragmented High Entropy Cluster',
    severity: 'MEDIUM',
    confidence: 'medium',
    domain: 'malware',
    description: 'Cluster de chaines courtes a haute entropie (8-49 chars) detecte. Technique de fragmentation de payload pour contourner le seuil de longueur minimum d\'analyse entropique.',
    references: ['https://attack.mitre.org/techniques/T1027/'],
    mitre: 'T1027'
  },
  js_obfuscation_pattern: {
    id: 'MUADDIB-ENTROPY-003',
    name: 'JS Obfuscation Pattern',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    severity: 'LOW',
    confidence: 'high',
    domain: 'author',
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
    domain: 'author',
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
    domain: 'author',
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
    domain: 'author',
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
    domain: 'author',
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
    domain: 'author',
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
    domain: 'author',
    description: 'La derniere version a ete publiee par un utilisateur different de la version precedente. Verifier la legitimite.',
    references: [
      'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident'
    ],
    mitre: 'T1195.002'
  },
  unclaimed_maintainer_email: {
    id: 'MUADDIB-MAINTAINER-005',
    name: 'Unclaimed Maintainer Email Domain',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'author',
    description: 'Le domaine de l\'email du mainteneur n\'a aucun MX record valide. Un attaquant peut enregistrer le domaine, creer la boite mail, declencher un reset de mot de passe npm, prendre le compte. Signal composite-only (HIGH x medium = 8.5 pts isole, sous T1).',
    references: [
      'https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/metadata/npm/unclaimed_maintainer_email_domain.py',
      'https://attack.mitre.org/techniques/T1556/'
    ],
    mitre: 'T1556'
  },
  compromised_email_domain: {
    id: 'MUADDIB-MAINTAINER-006',
    name: 'Compromised Maintainer Email Domain',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'author',
    description: 'Le domaine de l\'email du mainteneur a ete enregistre APRES la premiere publication du package (marge 30j). Pattern de rachat de domaine expire: l\'attaquant reprend le mail, declenche un reset de mot de passe npm, prend le compte. Signal composite-only (HIGH x high = 10 pts isole, sous T1).',
    references: [
      'https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/metadata/npm/potentially_compromised_email_domain.py',
      'https://attack.mitre.org/techniques/T1556/',
      'https://datatracker.ietf.org/doc/html/rfc7480'
    ],
    mitre: 'T1556'
  },

  // Canary token detections
  canary_exfiltration: {
    id: 'MUADDIB-CANARY-001',
    name: 'Canary Token Exfiltration',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
    description: 'Module WebAssembly charge sans sink reseau detectable. Usage legitime frequent (cryptographie, traitement d\'image, codecs). Le WASM cache le flux de controle — verifier le fichier .wasm manuellement.',
    references: ['https://attack.mitre.org/techniques/T1027/'],
    mitre: 'T1027'
  },
  credential_regex_harvest: {
    id: 'MUADDIB-AST-041',
    name: 'Credential Regex Harvesting',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
    description: 'Evasion IFS: curl$IFS ou curl${IFS} pipe vers shell. Technique d\'evasion pour contourner la detection de curl|sh en utilisant $IFS comme separateur.',
    references: ['https://attack.mitre.org/techniques/T1059/004/'],
    mitre: 'T1059.004'
  },
  eval_curl_subshell: {
    id: 'MUADDIB-SHELL-017',
    name: 'Eval Curl Command Substitution',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'eval $(curl ...) detecte. Telecharge et execute du code distant via command substitution.',
    references: ['https://attack.mitre.org/techniques/T1059/004/'],
    mitre: 'T1059.004'
  },
  sh_c_curl_exec: {
    id: 'MUADDIB-SHELL-018',
    name: 'Shell -c Curl Execution',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'sh -c wrapping autour de curl. Technique d\'evasion pour masquer l\'execution de commandes distantes.',
    references: ['https://attack.mitre.org/techniques/T1059/004/'],
    mitre: 'T1059.004'
  },
  python_time_delay_exec: {
    id: 'MUADDIB-SHELL-019',
    name: 'Python Time Delay Execution',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: 'Execution Python avec delai time.sleep() >= 100s via child process. Technique d\'evasion sandbox (T1497.003) : le malware attend que la sandbox expire avant d\'executer le payload.',
    references: ['https://attack.mitre.org/techniques/T1497/003/'],
    mitre: 'T1497.003'
  },

  // Intent Graph rules (v2.6.0)
  detached_credential_exfil: {
    id: 'MUADDIB-AST-047',
    name: 'Detached Process Credential Exfiltration',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
    description: 'Import Solana/Web3 + appel API C2 (getSignaturesForAddress, getTransaction). Technique GlassWorm: la blockchain sert de dead drop resolver pour obtenir l\'adresse C2 via le champ memo des transactions.',
    references: [
      'https://www.sonatype.com/blog/hijacked-npm-packages-deliver-malware-via-solana-linked-to-glassworm',
      'https://attack.mitre.org/techniques/T1102/'
    ],
    mitre: 'T1102'
  },
  dangerous_constructor: {
    id: 'MUADDIB-AST-057',
    name: 'AsyncFunction/GeneratorFunction Constructor via Prototype Chain',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Acces au constructeur AsyncFunction ou GeneratorFunction via Object.getPrototypeOf(). Technique d\'evasion permettant d\'executer du code arbitraire sans reference directe a eval() ou Function().',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/AsyncFunction',
      'https://attack.mitre.org/techniques/T1059/007/'
    ],
    mitre: 'T1059.007'
  },
  split_entropy_payload: {
    id: 'MUADDIB-AST-058',
    name: 'Split High-Entropy Payload',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Payload haute entropie fragmente en ≥3 chunks concatenes pour contourner la detection par string individuelle. Le resultat concatene passe par eval/Function/atob/Buffer.from, indiquant un dechiffrement ou une execution staged.',
    references: [
      'https://attack.mitre.org/techniques/T1027/002/',
      'https://attack.mitre.org/techniques/T1140/'
    ],
    mitre: 'T1027.002'
  },
  module_load_bypass: {
    id: 'MUADDIB-AST-056',
    name: 'Module._load() Internal Loader Bypass',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Module._load() detecte — bypass du module loader interne de Node.js pour charger dynamiquement des modules sans passer par require(). Technique d\'evasion contournant les restrictions de chargement de modules.',
    references: [
      'https://nodejs.org/api/modules.html',
      'https://attack.mitre.org/techniques/T1059/007/'
    ],
    mitre: 'T1059.007'
  },

  blockchain_rpc_endpoint: {
    id: 'MUADDIB-AST-055',
    name: 'Hardcoded Blockchain RPC Endpoint',
    severity: 'MEDIUM',
    confidence: 'medium',
    domain: 'malware',
    description: 'Endpoint RPC blockchain hardcode (Solana mainnet, Infura Ethereum). Dans un package non-crypto, indique un potentiel canal C2 via blockchain.',
    references: [
      'https://www.koi.security/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace',
      'https://attack.mitre.org/techniques/T1102/'
    ],
    mitre: 'T1102'
  },

  // v2.10.11 — TeamPCP/CanisterWorm campaign detections (mars 2026)
  systemd_persistence: {
    id: 'MUADDIB-AST-059',
    name: 'Systemd Service Persistence',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Ecriture dans un chemin systemd (*.service, systemd/) ou execution de systemctl enable/start. Technique de persistence CanisterWorm (pgmon.service) et TeamPCP (sysmon.service). Aucun package npm legitime ne cree de services systemd.',
    references: [
      'https://research.jfrog.com/post/canister-worm/',
      'https://attack.mitre.org/techniques/T1543/002/'
    ],
    mitre: 'T1543.002'
  },
  pth_persistence: {
    id: 'MUADDIB-AST-061',
    name: 'Python .pth Auto-Exec Persistence',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Ecriture d\'un fichier .pth detectee. Les fichiers .pth dans site-packages/ sont executes automatiquement par l\'interpreteur Python au demarrage, sans import explicite. Technique de persistence LiteLLM/Checkmarx (litellm_init.pth) : le .pth contient du code Python base64-encode qui installe un stealer.',
    references: [
      'https://blog.pypi.org/posts/2026-03-24-litellm-compromise/',
      'https://attack.mitre.org/techniques/T1546/004/'
    ],
    mitre: 'T1546.004'
  },
  npm_token_steal: {
    id: 'MUADDIB-AST-060',
    name: 'NPM Token Extraction via CLI',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Execution de npm config get _authToken ou npm whoami — extraction programmatique de credentials npm. Pattern CanisterWorm findNpmTokens() utilise pour la propagation worm.',
    references: [
      'https://research.jfrog.com/post/canister-worm/',
      'https://www.aikido.dev/blog/teampcp-deploys-worm-npm-trivy-compromise'
    ],
    mitre: 'T1552.001'
  },
  root_filesystem_wipe: {
    id: 'MUADDIB-SHELL-020',
    name: 'Root Filesystem Wipe',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Commande rm -rf / detectee — suppression de tout le systeme de fichiers. Pattern kamikaze.sh (CanisterWorm wiper ciblant Iran via timezone Asia/Tehran). Plus destructif que home_deletion.',
    references: [
      'https://www.aikido.dev/blog/teampcp-stage-payload-canisterworm-iran',
      'https://attack.mitre.org/techniques/T1485/'
    ],
    mitre: 'T1485'
  },
  proc_mem_scan: {
    id: 'MUADDIB-SHELL-021',
    name: 'Process Memory Scanning',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Acces a /proc/*/mem detecte — extraction de secrets depuis la memoire des processus. Technique TeamPCP credential stealer (Trivy v0.69.4) : scan des process Runner.Worker pour extraire les secrets CI/CD.',
    references: [
      'https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack',
      'https://attack.mitre.org/techniques/T1003/007/'
    ],
    mitre: 'T1003.007'
  },

  // Compound scoring rules (v2.9.2)
  // Injected by applyCompoundBoosts() when co-occurring threat types indicate unambiguous malice.
  crypto_staged_payload: {
    id: 'MUADDIB-COMPOUND-001',
    name: 'Steganographic Payload + Crypto Decryption',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
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
    domain: 'malware',
    description: 'Script lifecycle avec require(http/https) pour charger du code distant. Le payload est telecharge et execute automatiquement a l\'installation.',
    references: [
      'https://attack.mitre.org/techniques/T1105/',
      'https://attack.mitre.org/techniques/T1195/002/'
    ],
    mitre: 'T1105'
  },
  lifecycle_file_exec: {
    id: 'MUADDIB-COMPOUND-007',
    name: 'Lifecycle Script Executes Malicious File',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Un script lifecycle (preinstall/install/postinstall) reference un fichier JS local qui contient des menaces HIGH/CRITICAL. Indicateur fort de malware install-time: le fichier malveillant est cache derriere une indirection lifecycle.',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm',
      'https://attack.mitre.org/techniques/T1204/002/'
    ],
    mitre: 'T1204.002'
  },
  websocket_credential_exfil: {
    id: 'MUADDIB-COMPOUND-006',
    name: 'WebSocket/MQTT Credential Exfiltration',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Acces a une variable d\'environnement sensible combine avec un sink reseau non-HTTP (WebSocket, MQTT, Socket.io) dans le meme fichier. Canal d\'exfiltration furtif evitant les proxies HTTP.',
    references: [
      'https://attack.mitre.org/techniques/T1041/',
      'https://attack.mitre.org/techniques/T1071/001/'
    ],
    mitre: 'T1041'
  },
  uncaught_exception_exfil: {
    id: 'MUADDIB-COMPOUND-008',
    name: 'Uncaught Exception Handler Credential Exfiltration',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'process.on("uncaughtException") combine avec acces aux variables d\'environnement sensibles et appel reseau. Technique d\'exfiltration silencieuse: le handler intercepte les erreurs pour envoyer les credentials a un serveur externe sans interruption du processus.',
    references: [
      'https://attack.mitre.org/techniques/T1041/',
      'https://nodejs.org/api/process.html#event-uncaughtexception'
    ],
    mitre: 'T1041'
  },
  // C3 compounds (post-audit fondamental)
  lifecycle_dataflow: {
    id: 'MUADDIB-COMPOUND-009',
    name: 'Lifecycle Hook + Suspicious Dataflow',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Script lifecycle (preinstall/postinstall) combine avec un flux de donnees suspect (credential read → network send). Pattern classique d\'exfiltration install-time.',
    references: [
      'https://attack.mitre.org/techniques/T1041/',
      'https://attack.mitre.org/techniques/T1195/002/'
    ],
    mitre: 'T1041'
  },
  lifecycle_dangerous_exec: {
    id: 'MUADDIB-COMPOUND-010',
    name: 'Lifecycle Hook + Dangerous Shell Execution',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Script lifecycle combine avec execution de commande shell dangereuse (curl, wget, nc, bash). Injection de commande automatique a l\'installation.',
    references: [
      'https://attack.mitre.org/techniques/T1059/004/',
      'https://attack.mitre.org/techniques/T1195/002/'
    ],
    mitre: 'T1059.004'
  },
  obfuscated_lifecycle_env: {
    id: 'MUADDIB-COMPOUND-011',
    name: 'Obfuscated Lifecycle Credential Access',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Obfuscation + acces aux variables d\'environnement sensibles + script lifecycle. Triple signal: le code est intentionnellement masque pour voler des credentials a l\'installation.',
    references: [
      'https://attack.mitre.org/techniques/T1027/',
      'https://attack.mitre.org/techniques/T1552/001/'
    ],
    mitre: 'T1027'
  },
  suspicious_module_sink: {
    id: 'MUADDIB-FLOW-005',
    name: 'Non-HTTP Network Module Sink',
    severity: 'MEDIUM',
    confidence: 'medium',
    domain: 'malware',
    description: 'Utilisation d\'un module reseau non-HTTP (ws, mqtt, socket.io) comme sink de donnees. Ces modules sont rarement utilises dans les packages benins et peuvent indiquer un canal d\'exfiltration furtif.',
    references: [
      'https://attack.mitre.org/techniques/T1071/'
    ],
    mitre: 'T1071'
  },
  large_package_graph_truncated: {
    id: 'MUADDIB-FLOW-006',
    name: 'Large Package Graph Truncated',
    severity: 'MEDIUM',
    confidence: 'medium',
    domain: 'malware',
    description: 'Le graphe de modules depasse la limite (MAX_GRAPH_NODES). Cross-file dataflow non analyse — risque de blind spot sur monorepo ou large package. Auditer les sous-modules manuellement.',
    references: [
      'https://attack.mitre.org/techniques/T1195/002/'
    ],
    mitre: 'T1195.002'
  },

  // Audit v3 Bypass Detections (AST-062 to AST-069)
  reflect_apply_require: {
    id: 'MUADDIB-AST-062',
    name: 'Reflect.apply(require) Bypass',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Reflect.apply(require, null, [module]) detecte — contourne la detection statique de require() en passant par l\'API Reflect. Permet de charger child_process/fs/net sans appel require() direct.',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Reflect/apply',
      'https://attack.mitre.org/techniques/T1059/'
    ],
    mitre: 'T1059'
  },
  finalization_registry_exec: {
    id: 'MUADDIB-AST-063',
    name: 'FinalizationRegistry Deferred Execution',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'new FinalizationRegistry() avec callback contenant child_process/exec/spawn. Le callback s\'execute apres le garbage collection, hors du flux d\'execution normal — technique d\'evasion sandbox qui differe l\'execution malveillante.',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/FinalizationRegistry',
      'https://attack.mitre.org/techniques/T1497/003/'
    ],
    mitre: 'T1497.003'
  },
  function_prototype_constructor: {
    id: 'MUADDIB-AST-064',
    name: 'Function via Prototype Chain',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: '(function(){}).constructor(code) ou [].constructor.constructor(code) detecte — acces au constructeur Function via la chaine de prototypes, contourne les detections de new Function() et eval().',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function',
      'https://attack.mitre.org/techniques/T1059/'
    ],
    mitre: 'T1059'
  },
  prototype_pollution: {
    id: 'MUADDIB-AST-065',
    name: 'Prototype Pollution',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'vulnerability',
    description: '__defineGetter__, __defineSetter__ ou assignation __proto__ detectee — pollution de prototype permettant de detourner les proprietes heritees de tous les objets. Vecteur d\'escalade pour injecter du code dans des chemins d\'execution inattendus.',
    references: [
      'https://portswigger.net/web-security/prototype-pollution',
      'https://attack.mitre.org/techniques/T1574/'
    ],
    mitre: 'T1574'
  },
  module_wrap_override: {
    id: 'MUADDIB-AST-066',
    name: 'Module.wrap Override',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Module.wrap = ... detecte — remplacement de la fonction wrapper du module loader Node.js. Permet d\'injecter du code dans CHAQUE module charge apres le remplacement, technique de persistence systemique.',
    references: [
      'https://nodejs.org/api/modules.html',
      'https://attack.mitre.org/techniques/T1574/006/'
    ],
    mitre: 'T1574.006'
  },
  symbol_property_hiding: {
    id: 'MUADDIB-AST-067',
    name: 'Symbol Property Hiding',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'obj[Symbol(...)] = require(module_dangereux) detecte — dissimulation de modules dangereux derriere des proprietes Symbol, invisibles a Object.keys() et JSON.stringify(). Technique anti-forensics.',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Symbol',
      'https://attack.mitre.org/techniques/T1564/'
    ],
    mitre: 'T1564'
  },
  with_body_dangerous: {
    id: 'MUADDIB-AST-068',
    name: 'WithStatement Dangerous Body',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'with() statement dont le body contient require/exec/spawn/child_process — injection de scope pour obscurcir les appels dangereux. Le with() rend tous les identifiants ambigus, empechant l\'analyse statique de tracer les appels.',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/with',
      'https://attack.mitre.org/techniques/T1027/'
    ],
    mitre: 'T1027'
  },
  require_process_mainmodule: {
    id: 'MUADDIB-AST-069',
    name: 'require("process").mainModule Bypass',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'require("process").mainModule.require() detecte — acces indirect au mainModule via require("process") au lieu de l\'objet global process. Contourne la detection de process.mainModule.require() qui ne surveille que l\'identifiant "process".',
    references: [
      'https://nodejs.org/api/process.html',
      'https://attack.mitre.org/techniques/T1059/'
    ],
    mitre: 'T1059'
  },

  // Blue Team v8 — New detections (AST-070 to AST-077, SHELL-023, SCORE-001/002)
  shared_memory_ipc: {
    id: 'MUADDIB-AST-070',
    name: 'Shared Memory IPC',
    severity: 'MEDIUM',
    confidence: 'medium',
    domain: 'malware',
    description: 'SharedArrayBuffer + Worker Thread detectes — canal IPC memoire partagee qui contourne la surveillance des messages inter-threads.',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/SharedArrayBuffer',
      'https://attack.mitre.org/techniques/T1559/'
    ],
    mitre: 'T1559'
  },
  websocket_c2: {
    id: 'MUADDIB-AST-071',
    name: 'WebSocket C2 Channel',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Connexion WebSocket vers un domaine suspect ou avec execution dynamique — canal C2 bidirectionnel persistant.',
    references: [
      'https://attack.mitre.org/techniques/T1071.001/',
      'https://owasp.org/www-community/attacks/WebSocket_Hijacking'
    ],
    mitre: 'T1071.001'
  },
  udp_exfiltration: {
    id: 'MUADDIB-AST-072',
    name: 'UDP Data Exfiltration',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Module dgram (UDP) avec envoi de donnees — exfiltration via protocole UDP qui contourne les firewalls HTTP.',
    references: [
      'https://nodejs.org/api/dgram.html',
      'https://attack.mitre.org/techniques/T1048.003/'
    ],
    mitre: 'T1048.003'
  },
  native_addon_install: {
    id: 'MUADDIB-AST-073',
    name: 'Native Addon Installation',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: 'binding.gyp present avec script lifecycle non-standard — compilation native potentiellement malveillante a l\'installation.',
    references: [
      'https://nodejs.org/api/addons.html',
      'https://attack.mitre.org/techniques/T1195.002/'
    ],
    mitre: 'T1195.002'
  },
  string_mutation_obfuscation: {
    id: 'MUADDIB-AST-074',
    name: 'String Mutation Obfuscation',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Chaine de 3+ appels .replace() pour reconstruire des noms d\'API dangereuses — technique leet-speak/substitution pour contourner la detection statique.',
    references: [
      'https://attack.mitre.org/techniques/T1027/',
      'https://attack.mitre.org/techniques/T1140/'
    ],
    mitre: 'T1027'
  },
  crontab_systemd_write: {
    id: 'MUADDIB-SHELL-023',
    name: 'Crontab/Cron Write',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Ecriture dans les fichiers cron (/etc/cron*, crontab, /var/spool/cron) — persistence via tache planifiee.',
    references: [
      'https://attack.mitre.org/techniques/T1053.003/',
      'https://attack.mitre.org/techniques/T1543/'
    ],
    mitre: 'T1053.003'
  },
  isolated_suspicious_file: {
    id: 'MUADDIB-SCORE-001',
    name: 'Isolated Suspicious File',
    severity: 'MEDIUM',
    confidence: 'medium',
    domain: 'malware',
    description: 'Un seul fichier suspect parmi 10+ fichiers propres — pattern de dissimulation ou le code malveillant est cache dans un package legitime.',
    references: [
      'https://attack.mitre.org/techniques/T1036/'
    ],
    mitre: 'T1036'
  },
  deep_suspicious_file: {
    id: 'MUADDIB-SCORE-002',
    name: 'Deeply Nested Suspicious File',
    severity: 'LOW',
    confidence: 'low',
    domain: 'malware',
    description: 'Pattern suspect detecte dans un fichier profondement imbrique (profondeur > 3) — technique de dissimulation dans l\'arborescence du package.',
    references: [
      'https://attack.mitre.org/techniques/T1036.005/'
    ],
    mitre: 'T1036.005'
  },

  // Blue Team v8b — New detections (AST-075 to AST-082, PKG-017)
  module_internals_hijack: {
    id: 'MUADDIB-AST-075',
    name: 'Module Internals Hijack',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Assignation a Module._resolveFilename, _compile ou _extensions — detournement des mecanismes internes du systeme de modules Node.js. Tous les require() subsequents peuvent etre interceptes.',
    references: [
      'https://nodejs.org/api/modules.html',
      'https://attack.mitre.org/techniques/T1574.006/'
    ],
    mitre: 'T1574.006'
  },
  json_reviver_pollution: {
    id: 'MUADDIB-AST-076',
    name: 'JSON Reviver Prototype Pollution',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'vulnerability',
    description: 'JSON.parse avec fonction reviver accedant a __proto__ ou prototype — pollution de prototype via donnees JSON non fiables.',
    references: [
      'https://portswigger.net/web-security/prototype-pollution',
      'https://attack.mitre.org/techniques/T1059.007/'
    ],
    mitre: 'T1059.007'
  },
  vm_dynamic_code: {
    id: 'MUADDIB-AST-077',
    name: 'VM Dynamic Code Execution',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'vm.runInContext/runInNewContext/compileFunction avec code construit dynamiquement — evasion du sandbox via code genere au runtime.',
    references: [
      'https://nodejs.org/api/vm.html',
      'https://attack.mitre.org/techniques/T1059.007/'
    ],
    mitre: 'T1059.007'
  },
  callback_exec_rce: {
    id: 'MUADDIB-AST-078',
    name: 'Callback Remote Code Execution',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'exec/spawn dans un callback .on(\'message\') ou .on(\'data\') avec child_process — execution de commandes a distance depuis un flux reseau.',
    references: [
      'https://attack.mitre.org/techniques/T1059/',
      'https://attack.mitre.org/techniques/T1071/'
    ],
    mitre: 'T1059'
  },
  stego_binary_exec: {
    id: 'MUADDIB-AST-079',
    name: 'Steganographic Binary Execution',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Lecture de fichier binaire/image (PNG, JPG) + execution dynamique (eval/Function) — extraction et execution de payload steganographique.',
    references: [
      'https://attack.mitre.org/techniques/T1027.003/',
      'https://attack.mitre.org/techniques/T1140/'
    ],
    mitre: 'T1027.003'
  },
  asynclocal_context_exec: {
    id: 'MUADDIB-AST-080',
    name: 'AsyncLocalStorage Context Execution',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: 'AsyncLocalStorage + execution dynamique — code malveillant cache dans un contexte asynchrone, echappe a l\'analyse de pile d\'appels synchrone.',
    references: [
      'https://nodejs.org/api/async_context.html',
      'https://attack.mitre.org/techniques/T1059.007/'
    ],
    mitre: 'T1059.007'
  },
  prototype_chain_constructor: {
    id: 'MUADDIB-AST-081',
    name: 'Prototype Chain Constructor Access via Variable',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Object.getPrototypeOf(variable).constructor extrait dans une variable — traversee de la chaine de prototypes pour atteindre le constructeur Function et executer du code arbitraire.',
    references: [
      'https://attack.mitre.org/techniques/T1059.007/',
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/getPrototypeOf'
    ],
    mitre: 'T1059.007'
  },
  ci_environment_probe: {
    id: 'MUADDIB-AST-082',
    name: 'CI Environment Fingerprinting',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: 'References a 3+ variables d\'environnement de fournisseurs CI (GITHUB_ACTIONS, GITLAB_CI, etc.) — sondage d\'environnement CI pour activation conditionnelle de payload.',
    references: [
      'https://attack.mitre.org/techniques/T1082/',
      'https://attack.mitre.org/techniques/T1497/'
    ],
    mitre: 'T1082'
  },
  proxy_globalthis_intercept: {
    id: 'MUADDIB-AST-083',
    name: 'Proxy GlobalThis Interception',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'new Proxy(globalThis/global/window/self) — intercepts all global scope access, enabling transparent hooking of eval/Function/require.',
    references: ['https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Proxy'],
    mitre: 'T1574'
  },
  reflect_bind_code_execution: {
    id: 'MUADDIB-AST-084',
    name: 'Reflect.apply Prototype Method Code Execution',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Reflect.apply(Function.prototype.bind/call/apply, Function, [...]) — indirect code execution via Reflect with prototype method as target.',
    references: ['https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Reflect/apply'],
    mitre: 'T1059'
  },
  timer_delayed_payload: {
    id: 'MUADDIB-AST-085',
    name: 'Timer Delayed Payload',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'setTimeout/setInterval avec delai >= 60s contenant un sink dangereux (eval/exec/spawn/Function) dans le callback. Evasion temporelle: le payload s\'active apres le timeout des sandboxes. Technique PhantomRaven/timer-bomb-exfil.',
    references: [
      'https://attack.mitre.org/techniques/T1497/003/',
      'https://www.sonatype.com/blog/phantomraven-supply-chain-attack'
    ],
    mitre: 'T1497.003'
  },
  lifecycle_missing_script: {
    id: 'MUADDIB-PKG-017',
    name: 'Phantom Lifecycle Script',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Script lifecycle (preinstall/install) reference un fichier qui n\'existe pas dans le package — script fantome, le payload peut etre injecte au moment de la publication.',
    references: [
      'https://attack.mitre.org/techniques/T1195.002/',
      'https://blog.npmjs.org/post/166316363605/the-lifecycle-script-vulnerability'
    ],
    mitre: 'T1195.002'
  },
  // v2.10.89: Security review findings (apr-2026) — 5 new rules from 14K tarball review
  curl_env_exfil: {
    id: 'MUADDIB-PKG-018',
    name: 'Curl/Wget Environment Exfiltration',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'curl/wget combine avec base64 ou env dans un lifecycle script — exfiltration de credentials a l\'installation. Pattern: curl -d $(env|base64) URL dans preinstall/postinstall.',
    references: [
      'https://attack.mitre.org/techniques/T1041/',
      'https://blog.phylum.io/npm-dependency-confusion-attacks'
    ],
    mitre: 'T1041'
  },
  function_constructor_require: {
    id: 'MUADDIB-AST-086',
    name: 'Function Constructor Require Evasion',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'new Function.constructor("require", code) — execution de code dynamique via le constructeur Function avec acces au require reel. Technique d\'evasion: contourne la detection de eval/require en passant par le prototype de Function.',
    references: [
      'https://attack.mitre.org/techniques/T1059/007/'
    ],
    mitre: 'T1059.007'
  },
  process_variable_shadow: {
    id: 'MUADDIB-AST-087',
    name: 'Process Variable Shadowing',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Le global process est shadow par une variable locale (const process = {...}). Technique d\'evasion: cache les URLs C2 dans un faux process.env pour contourner la detection de domaines suspects. Campagne "Robert King" (npoint.io/jsonkeeper.com).',
    references: [
      'https://attack.mitre.org/techniques/T1036/'
    ],
    mitre: 'T1036'
  },
  newsletter_auto_follow: {
    id: 'MUADDIB-AST-088',
    name: 'Baileys Newsletter Auto-Follow Hijack',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'malware',
    description: 'Pattern de detournement WhatsApp Baileys: newsletter + FOLLOW/QueryIds ou AUTO_FOLLOW_CHANNELS dans le meme fichier. Force l\'abonnement a des channels WhatsApp via la session authentifiee de la victime sans consentement.',
    references: [
      'https://attack.mitre.org/techniques/T1496/'
    ],
    mitre: 'T1496'
  },
  self_destruct_eval: {
    id: 'MUADDIB-AST-089',
    name: 'Self-Destructing Dynamic Execution',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Execution dynamique de code (eval/new Function/Module._compile) combinee a la suppression ou renommage du fichier en cours d\'execution (unlinkSync/rmSync/renameSync sur __filename, module.filename, ou require.main.filename). Anti-forensics: le malware execute son payload obfusque puis efface ses traces. Aucun package legitime ne detruit son propre source apres execution de code dynamique. Campagne csec-crypto-toolkit (avril 2026): XOR(OrDeR_7077)+base64+new Function, exfiltre .env/.ssh/.npmrc vers csec-supply-chain-attack.vercel.app, puis unlinkSync(__filename).',
    references: [
      'https://attack.mitre.org/techniques/T1070.004/',
      'https://attack.mitre.org/techniques/T1140/'
    ],
    mitre: 'T1070.004'
  },
  function_runtime_args: {
    id: 'MUADDIB-AST-090',
    name: 'Function() with Runtime Identifiers as Arguments',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'new Function() appele avec des identifiants runtime (require, __dirname, __filename, module, exports, process) passes comme arguments string literal, et un corps dynamique (variable, expression). Pattern csec-crypto-toolkit: l\'attaquant injecte le contexte Node complet dans un payload obfusque execute en memoire, contournant la detection require() standard. Aucun package legitime ne passe require + __filename a new Function.',
    references: [
      'https://attack.mitre.org/techniques/T1059.007/',
      'https://attack.mitre.org/techniques/T1027/'
    ],
    mitre: 'T1059.007'
  },
  geo_evasion_killswitch: {
    id: 'MUADDIB-AST-091',
    name: 'Geo-Evasion CIS Kill Switch',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: 'Code verifie la locale systeme (Intl.DateTimeFormat, LC_ALL/LANG) pour "ru" et fait process.exit — technique CIS kill switch pour eviter de cibler les pays de l\'operateur. Pattern TeamPCP/Shai-Hulud.',
    references: [
      'https://github.com/g00dfe11ow/Shai-Hulud-Open-Source',
      'https://attack.mitre.org/techniques/T1614/'
    ],
    mitre: 'T1614'
  },
  external_tarball_dep: {
    id: 'MUADDIB-PKG-020',
    name: 'External Tarball Dependency URL',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'malware',
    description: 'Dependance declaree avec une URL tarball (.tgz/.tar.gz/.tar.bz2/.zip) hebergee hors des registres npm legitimes (github.com, gitlab.com, bitbucket.org, registry.npmjs.org, registry.yarnpkg.com). Pattern ltidi chain attack (avril 2026): le stub publie sur npm n\'a pas d\'install hook visible, la charge utile est hebergee sur un cloud storage (GCS, S3, CDN) et contourne entierement l\'audit du registre npm. Attention: MT-1 score ceiling (cap non-lifecycle a 35) bypasse via HIGH_CONFIDENCE_MALICE_TYPES.',
    references: [
      'https://attack.mitre.org/techniques/T1195.002/',
      'https://attack.mitre.org/techniques/T1105/'
    ],
    mitre: 'T1195.002'
  },
  version_99_preinstall: {
    id: 'MUADDIB-PKG-019',
    name: 'Dependency Confusion Version Indicator',
    severity: 'HIGH',
    confidence: 'high',
    domain: 'engineering',
    description: 'Version >= 99.x.x avec hook lifecycle (preinstall/postinstall). Indicateur fort de dependency confusion: la version elevee force la resolution npm vers le package public malveillant au lieu du package interne prive.',
    references: [
      'https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610',
      'https://attack.mitre.org/techniques/T1195.002/'
    ],
    mitre: 'T1195.002'
  },
  release_zero_package: {
    id: 'MUADDIB-PKG-022',
    name: 'Release Zero Package',
    severity: 'MEDIUM',
    confidence: 'high',
    domain: 'engineering',
    description: 'Package publie en version 0.0.0 / 0.0 / 0 combine avec install scripts ou publication recente (<30j). Pattern de squat de namespace ou placeholder pre-payload. Conjonction (zero-version AND (scripts OR recent)) pour eviter les FP sur placeholders abandonnes.',
    references: [
      'https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/metadata/npm/release_zero.py',
      'https://attack.mitre.org/techniques/T1195.002/'
    ],
    mitre: 'T1195.002'
  },
  // Trusted dependency diff detections (monitor-only)
  trusted_new_unknown_dependency: {
    id: 'MUADDIB-TRUSTED-001',
    name: 'Trusted Package Added Unknown Dependency',
    severity: 'CRITICAL',
    confidence: 'high',
    domain: 'author',
    description: 'Un package TRUSTED (>50k downloads/semaine) a ajoute une nouvelle dependance inconnue ou tres recente (<7 jours) — indicateur de compromission de compte mainteneur (supply-chain attack type axios/plain-crypto-js).',
    references: [
      'https://attack.mitre.org/techniques/T1195.002/',
      'https://blog.sonatype.com/malicious-npm-packages-targeting-popular-libraries'
    ],
    mitre: 'T1195.002'
  },
  trusted_new_dependency: {
    id: 'MUADDIB-TRUSTED-002',
    name: 'Trusted Package Added New Dependency',
    severity: 'HIGH',
    confidence: 'medium',
    domain: 'malware',
    description: 'Un package TRUSTED (>50k downloads/semaine) a ajoute une nouvelle dependance connue (>7 jours) dans un bump de version — changement de surface d\'attaque a verifier.',
    references: [
      'https://attack.mitre.org/techniques/T1195.002/'
    ],
    mitre: 'T1195.002'
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
    domain: 'unknown',
    description: 'Menace non categorisee',
    references: [],
    mitre: null
  };
}

/**
 * Resolve the risk domain for a given threat type. Returns the rule's declared
 * `domain` field if set, otherwise 'malware' (the safe default — most untagged
 * threats are malware-class detections). Returns 'unknown' only for fully
 * unknown threat types (no rule + no paranoid match).
 *
 * Phase rollout: as the ~217 remaining untagged rules get a `domain` field,
 * the 'malware' default rate will decrease toward zero.
 */
function getRuleDomain(type) {
  const rule = getRule(type);
  if (rule && typeof rule.domain === 'string' && VALID_DOMAINS.has(rule.domain)) {
    return rule.domain;
  }
  // Fallback for the unknown-rule path
  if (rule && rule.id === 'MUADDIB-UNK-001') return 'unknown';
  // Default for untagged but otherwise valid rules — most rules are malware-class
  return 'malware';
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

// Validate all rules at load time
const VALID_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
const VALID_CONFIDENCES = new Set(['high', 'medium', 'low']);

for (const [key, rule] of Object.entries(RULES)) {
  if (!VALID_SEVERITIES.has(rule.severity)) {
    throw new Error(`Rule "${key}" has invalid severity: ${JSON.stringify(rule.severity)} (expected CRITICAL|HIGH|MEDIUM|LOW)`);
  }
  if (!VALID_CONFIDENCES.has(rule.confidence)) {
    throw new Error(`Rule "${key}" has invalid confidence: ${JSON.stringify(rule.confidence)} (expected high|medium|low)`);
  }
  // P0a: domain is optional during rollout — validated only if present.
  // Once all rules are tagged (P0a-5), make this mandatory.
  if (rule.domain !== undefined && !VALID_DOMAINS.has(rule.domain)) {
    throw new Error(`Rule "${key}" has invalid domain: ${JSON.stringify(rule.domain)} (expected ${Array.from(VALID_DOMAINS).join('|')})`);
  }
}
// PARANOID_RULES use a different schema (patterns/message, no confidence field)
for (const [key, rule] of Object.entries(PARANOID_RULES)) {
  if (!VALID_SEVERITIES.has(rule.severity)) {
    throw new Error(`Paranoid rule "${key}" has invalid severity: ${JSON.stringify(rule.severity)} (expected CRITICAL|HIGH|MEDIUM|LOW)`);
  }
}

module.exports = {
  RULES,
  getRule,
  PARANOID_RULES,
  // P0a — Risk Domains taxonomy
  RISK_DOMAINS,
  DOMAIN_CODES,
  VALID_DOMAINS,
  getRuleDomain
};