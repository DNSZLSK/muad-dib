const PLAYBOOKS = {
  lifecycle_script: 
    'Verifier le contenu du script. Desactiver avec "npm config set ignore-scripts true" si suspect.',
  
  curl_pipe_sh: 
    'CRITIQUE: Ne jamais executer. Inspecter l\'URL telechargee. Verifier si deja execute.',
  
  wget_pipe_sh:
    'CRITIQUE: Ne jamais executer. Inspecter l\'URL telechargee. Verifier si deja execute.',
  
  eval_usage:
    'Code dynamique detecte. Verifier la source des donnees evaluees. Risque d\'injection.',
  
  child_process:
    'Execution de commandes systeme. Verifier quelles commandes sont lancees.',
  
  child_process_import:
    'Module child_process importe. Verifier son utilisation dans le code.',
  
  npmrc_access:
    'Acces au fichier .npmrc detecte. Risque de vol de token npm. Regenerer le token.',
  
  github_token_access:
    'Acces au GITHUB_TOKEN. Verifier les permissions. Regenerer si compromis.',
  
  aws_credential_access:
    'Acces aux credentials AWS. Rotation immediate recommandee via AWS IAM.',
  
  sensitive_env_access:
    'Acces a des variables sensibles. Verifier l\'usage. Rotation des secrets recommandee.',
  
  base64_encoding:
    'Encodage base64 detecte. Souvent utilise pour obfusquer du code malveillant.',
  
  base64_decode:
    'Decodage base64 detecte. Verifier ce qui est decode et execute.',
  
  reverse_shell:
    'CRITIQUE: Reverse shell detecte. Machine potentiellement compromise. Isoler immediatement.',
  
  home_deletion:
    'CRITIQUE: Tentative de suppression du repertoire home. Dead man\'s switch probable.',
  
  curl_exfiltration:
    'Exfiltration de donnees via curl. Verifier les donnees envoyees et la destination.',
  
  ssh_access:
    'Acces aux cles SSH. Regenerer les cles si compromis: ssh-keygen -t ed25519',
  
  github_api_call:
    'Appel a l\'API GitHub. Verifier le contexte. Peut etre legitime ou exfiltration.',
  
  exec_curl:
    'Execution de curl via child_process. Verifier l\'URL et les donnees.',
  
  exec_wget:
    'Execution de wget via child_process. Verifier l\'URL et les donnees.',
  
  dynamic_require:
    'require() avec concatenation detecte. Technique d\'obfuscation pour masquer le module charge. Analyser les variables concatenees.',

  dangerous_exec:
    'CRITIQUE: Execution de commande shell dangereuse detectee. Isoler la machine. Verifier si la commande a ete executee.',

  staged_payload:
    'CRITIQUE: Code telecharge depuis le reseau et execute via eval(). Payload distant probable. Isoler et analyser le trafic reseau.',

  network_require:
    'require(https/http) dans un script lifecycle. Le package telecharge du code lors de l\'installation. Verifier l\'URL de destination.',

  node_inline_exec:
    'node -e dans un script lifecycle. Code inline execute a l\'installation. Analyser le code inline.',

  dynamic_import:
    'import() dynamique detecte. Technique d\'evasion pour eviter la detection de require(). Verifier quel module est charge et son usage.',

  env_proxy_intercept:
    'CRITIQUE: new Proxy(process.env) intercepte tous les acces aux variables d\'environnement. Technique d\'exfiltration silencieuse. Isoler la machine, regenerer tous les secrets.',

  dynamic_require_exec:
    'CRITIQUE: exec/execSync appele sur un module charge via require() obfusque. Le module child_process est dissimule par concatenation/encodage. Isoler la machine, auditer les commandes executees.',

  sandbox_evasion:
    'Code detecte la presence d\'un sandbox/container (/.dockerenv, /proc/cgroup). Technique anti-analyse: le malware adapte son comportement selon l\'environnement. Analyser les deux branches (sandbox vs production).',

  detached_process:
    'spawn/fork avec {detached: true} detecte. Le processus enfant survit a la fin de npm install et execute le payload en arriere-plan. Verifier les processus en cours: ps aux | grep node. Tuer le processus suspect.',

  known_malicious_package:
    'CRITIQUE: Supprimer immediatement. rm -rf node_modules && npm cache clean --force && npm install',

  pypi_malicious_package:
    'CRITIQUE: Supprimer immediatement. pip uninstall <package> && pip install -r requirements.txt',

  pypi_typosquat_detected:
    'Verifier que le nom du package PyPI est correct. Comparer avec le package populaire identifie.',

  lifecycle_script_dependency:
    'Verifier le contenu du script dans le package. Reinstaller avec --ignore-scripts si suspect.',

  suspicious_file:
    'Fichier typique de Shai-Hulud. Ne pas executer. Verifier le hash contre les IOCs connus.',

  obfuscation_detected:
    'Code volontairement obscurci. Analyser dans un environnement isole. Probable malware.',

  dangerous_call_eval:
    'Appel eval() detecte. Verifier la source des donnees. Risque d\'execution de code arbitraire.',

  dangerous_call_exec:
    'Execution de commande systeme. Verifier les arguments passes.',

  dangerous_call_spawn:
    'Spawn de processus detecte. Verifier la commande executee.',

  sensitive_string:
    'Reference a un chemin ou identifiant sensible. Verifier le contexte d\'utilisation.',

  env_access:
    'Acces a une variable d\'environnement sensible. Verifier si les donnees sont exfiltrees.',

  shai_hulud_marker:
    'CRITIQUE: Marqueur Shai-Hulud detecte. Package compromis. Supprimer immediatement et regenerer tous les tokens.',

  known_malicious_hash:
    'CRITIQUE: Fichier malveillant confirme par hash. Supprimer immediatement. Considerer la machine compromise.',

  suspicious_dataflow:
    'CRITIQUE: Code lit des credentials et les envoie sur le reseau. Exfiltration probable. Isoler la machine, regenerer tous les secrets.',

  typosquat_detected:
    'ATTENTION: Ce package a un nom tres similaire a un package populaire. Verifier que c\'est bien le bon package. Si erreur de frappe, corriger immediatement.',

  dangerous_call_function:
    'Appel new Function() detecte. Equivalent a eval(). Verifier la source des donnees.',

  possible_obfuscation:
    'Fichier potentiellement obfusque (parse echoue, code dense). Analyser manuellement.',

  curl_pipe_shell:
    'CRITIQUE: Telechargement et execution via curl | sh. Ne jamais executer. Inspecter l\'URL.',

  wget_chmod_exec:
    'CRITIQUE: Telechargement et execution via wget + chmod. Ne jamais executer. Inspecter le binaire.',

  netcat_shell:
    'CRITIQUE: Shell netcat detecte. Machine potentiellement compromise. Isoler immediatement.',

  shred_home:
    'CRITIQUE: Destruction de donnees detectee. Dead man\'s switch de Shai-Hulud. Isoler la machine.',

  npmrc_read:
    'Lecture du .npmrc. Regenerer immediatement: npm token revoke && npm login',

  ssh_key_read:
    'Lecture des cles SSH. Regenerer immediatement toutes les cles: ssh-keygen -t ed25519',

  python_reverse_shell:
    'CRITIQUE: Reverse shell Python detecte. Machine potentiellement compromise. Isoler immediatement.',
  perl_reverse_shell:
    'CRITIQUE: Reverse shell Perl detecte. Machine potentiellement compromise. Isoler immediatement.',
  fifo_reverse_shell:
    'CRITIQUE: Reverse shell FIFO/named pipe detecte. Machine potentiellement compromise. Isoler immediatement.',

  shai_hulud_backdoor:
    'CRITIQUE: Backdoor Shai-Hulud dans GitHub Actions. Supprimer le workflow et auditer les runs precedents.',

  workflow_injection:
    'Injection potentielle dans GitHub Actions via input non sanitise sur self-hosted runner. Supprimer ou corriger le workflow.',

  sandbox_sensitive_file_read:
    'CRITIQUE: Package lit des fichiers sensibles (credentials) lors de l\'installation. Ne pas installer. Supprimer immediatement.',
  sandbox_sensitive_file_write:
    'CRITIQUE: Package ecrit dans des fichiers sensibles lors de l\'installation. Considerer la machine compromise.',
  sandbox_suspicious_filesystem:
    'Package modifie des fichiers systeme lors de l\'installation. Analyser les chemins cibles.',
  sandbox_suspicious_dns:
    'Package resout des domaines non-registry lors de l\'installation. Verifier les domaines contactes.',
  sandbox_suspicious_connection:
    'Package etablit des connexions reseau suspectes lors de l\'installation. Analyser les destinations.',
  sandbox_suspicious_process:
    'CRITIQUE: Package execute des commandes dangereuses (curl, wget, nc) lors de l\'installation. Ne pas installer.',
  sandbox_unknown_process:
    'Package lance des processus inconnus lors de l\'installation. Verifier les commandes executees.',
  sandbox_timeout:
    'CRITIQUE: Le container sandbox a depasse le timeout. Possible boucle infinie ou consommation de ressources.',

  high_entropy_string:
    'Chaine a haute entropie detectee. Verifier si c\'est du base64, hex, ou un payload chiffre. Analyser le contexte d\'utilisation.',
  js_obfuscation_pattern:
    'Pattern d\'obfuscation JS detecte (variables _0x*, string arrays encodes, eval+payload, long base64). Analyser dans un sandbox. Comparer avec les signatures Shai-Hulud/chalk/debug.',

  lifecycle_added_critical:
    'CRITIQUE: Un script d\'installation (preinstall/install/postinstall) a ete ajoute dans la derniere version. ' +
    'C\'est le vecteur d\'attaque #1 des supply chain attacks (Shai-Hulud, ua-parser-js, coa). ' +
    'Actions: 1. NE PAS installer cette version. ' +
    '2. Verifier le changelog officiel du package. ' +
    '3. Comparer avec la version precedente: npm diff package@old package@new. ' +
    '4. Si pas de justification legitime, signaler sur GitHub/npm.',

  lifecycle_added_high:
    'Un script lifecycle (prepare, prepack, etc.) a ete ajoute dans la derniere version. ' +
    'Verifier le changelog officiel. Comparer: npm diff package@old package@new. ' +
    'Si pas de justification, investiguer le mainteneur.',

  lifecycle_modified:
    'Un script lifecycle a ete modifie entre les deux dernieres versions. ' +
    'Verifier le contenu du nouveau script. Comparer: npm diff package@old package@new.',

  dangerous_api_added_critical:
    'CRITIQUE: Une API dangereuse (child_process, eval, Function, net.connect) est apparue dans la derniere version. ' +
    'Cette API etait absente de la version precedente. ' +
    'Actions: 1. NE PAS mettre a jour. ' +
    '2. Comparer les sources: npm diff package@old package@new. ' +
    '3. Verifier le changelog et les commits recents. ' +
    '4. Si pas de justification, signaler sur GitHub/npm.',

  dangerous_api_added_high:
    'Une API suspecte (process.env, fetch, http/https) est apparue dans la derniere version. ' +
    'Verifier si le changement est justifie dans le changelog. ' +
    'Comparer: npm diff package@old package@new.',

  dangerous_api_added_medium:
    'Une API potentiellement suspecte (dns.lookup, fs.readFile sur chemin sensible) est apparue. ' +
    'Verifier le contexte d\'utilisation. Comparer: npm diff package@old package@new.',

  publish_burst:
    'Multiple versions published rapidly. Possible account compromise. ' +
    'Verify maintainer activity on npm/GitHub. Check changelogs for each version.',

  dormant_spike:
    'Package dormant for 6+ months suddenly updated. ' +
    'Check if maintainer changed or account was compromised. ' +
    'Compare: npm diff package@old package@new.',

  rapid_succession:
    'Versions published in rapid succession. ' +
    'Could indicate automated attack or compromised CI/CD. ' +
    'Verify each version for malicious changes.',

  new_maintainer:
    'A new maintainer was added. Verify this is legitimate by checking the package\'s GitHub/npm page. ' +
    'Compare: npm diff package@old package@new.',

  suspicious_maintainer:
    'Maintainer has suspicious name pattern (generic/auto-generated). High risk of account takeover. ' +
    'Verify maintainer identity on npm and GitHub. Do NOT install until verified.',

  sole_maintainer_change:
    'The sole maintainer has changed. This is a strong indicator of account compromise (event-stream pattern). ' +
    'Verify on npm and GitHub. Compare: npm diff package@old package@new.',

  new_publisher:
    'New publisher detected. Package published by a different user than before. Verify legitimacy by checking the package\'s npm page and changelog.',

  credential_command_exec:
    'CRITIQUE: Le code utilise un outil CLI legitime (gh, gcloud, aws, az) pour voler des tokens. ' +
    'Verifier: gh auth status, gcloud auth list, aws sts get-caller-identity. ' +
    'Regenerer tous les tokens des outils concernes. Revoquer les sessions actives.',

  workflow_write:
    'Le code cree un fichier dans .github/workflows/ — injection de workflow GitHub Actions. ' +
    'Supprimer le fichier cree. Auditer les workflows existants. ' +
    'Verifier les GitHub Actions runs recents pour des executions non autorisees.',

  binary_dropper:
    'CRITIQUE: Pattern dropper detecte — fichier telecharge, rendu executable (chmod), et execute. ' +
    'Verifier /tmp pour des binaires suspects. Tuer les processus inconnus. ' +
    'Considerer la machine compromise si le binaire a ete execute.',

  prototype_hook:
    'Prototype de fonction native modifie (fetch, XMLHttpRequest, http.request). ' +
    'Technique d\'interception de trafic pour voler des donnees en transit. ' +
    'Supprimer le package. Auditer le trafic reseau recent.',

  ai_config_injection:
    'Fichier de config d\'agent IA contient des instructions malveillantes. ' +
    'NE PAS ouvrir le projet avec un agent IA sans verifier les fichiers .cursorrules, CLAUDE.md, copilot-instructions.md. ' +
    'Supprimer ou nettoyer ces fichiers avant toute utilisation. Technique ToxicSkills/Clinejection.',

  ai_config_injection_critical:
    'CRITIQUE: Fichier de config d\'agent IA contient des commandes d\'exfiltration ou un combo shell + credential access. ' +
    'NE PAS ouvrir ce projet avec un agent IA. Supprimer les fichiers de config compromis. ' +
    'Si deja ouvert avec un agent IA, considerer la machine compromise. Regenerer tous les secrets.',

  ai_agent_abuse:
    'CRITIQUE: Un agent IA (Claude, Gemini, Q) est invoque avec des flags de bypass de securite ' +
    '(--dangerously-skip-permissions, --yolo, --trust-all-tools). Technique s1ngularity/Nx. ' +
    'NE PAS installer. Verifier si l\'agent a ete execute. Si oui, considerer la machine compromise. ' +
    'Auditer les fichiers sensibles (.ssh, .aws, .env) pour des acces non autorises.',

  canary_exfiltration:
    'CRITIQUE: Le package a tente de voler des credentials (honey tokens). Comportement malveillant confirme. ' +
    'NE PAS installer. Signaler immediatement sur npm/PyPI. ' +
    'Si deja installe: considerer la machine compromise, regenerer TOUS les secrets.',

  env_charcode_reconstruction:
    'Obfuscation detectee: le nom de la variable d\'environnement est reconstruit dynamiquement via fromCharCode ' +
    'pour eviter la detection statique. Technique de vol de GITHUB_TOKEN, NPM_TOKEN, etc. ' +
    'Verifier quelles variables sont accedees et si elles sont exfiltrees.',

  lifecycle_shell_pipe:
    'CRITIQUE: Le script lifecycle (preinstall/postinstall) pipe du code distant vers un shell (curl | sh). ' +
    'NE PAS installer. Ceci execute du code arbitraire a l\'installation. ' +
    'Si deja installe: considerer la machine compromise. Auditer les modifications systeme.',

  cross_file_dataflow:
    'CRITIQUE: Un module lit des credentials et les exporte vers un autre module qui les envoie sur le reseau. ' +
    'Exfiltration inter-fichiers confirmee. Isoler la machine, supprimer le package, regenerer TOUS les secrets. ' +
    'Auditer les connexions reseau recentes pour identifier les donnees exfiltrees.',

  credential_tampering:
    'CRITIQUE: Ecriture detectee dans un cache sensible (npm _cacache, yarn, pip). ' +
    'Possible cache poisoning: injection de code malveillant dans des packages caches. ' +
    'Nettoyer le cache: npm cache clean --force. Reinstaller les dependances depuis zero.',

  require_cache_poison:
    'CRITIQUE: require.cache modifie pour hijacker des modules Node.js. ' +
    'Le code remplace les exports de modules charges (https, http, fs) pour intercepter toutes les requetes. ' +
    'Supprimer le package. Redemarrer le processus Node.js. Auditer le trafic reseau recent.',

  staged_binary_payload:
    'Fichier binaire (.png/.jpg/.wasm) reference avec eval() dans le meme fichier. ' +
    'Technique de steganographie: le payload malveillant est cache dans les pixels d\'une image ou les sections d\'un WASM. ' +
    'Analyser le fichier binaire dans un sandbox. Verifier les donnees extraites avant execution.',

  staged_eval_decode:
    'CRITIQUE: eval() ou Function() recoit un argument decode en base64 (atob/Buffer.from). ' +
    'Technique de staged payload: le code malveillant est encode puis decode et execute dynamiquement. ' +
    'Isoler la machine. Decoder le payload manuellement pour analyser le code execute. Supprimer le package.',
};

function getPlaybook(threatType) {
  return PLAYBOOKS[threatType] || 'Analyser manuellement cette menace.';
}

module.exports = { getPlaybook, PLAYBOOKS };