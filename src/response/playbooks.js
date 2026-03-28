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

  dependency_url_suspicious:
    'Dependance avec URL suspecte. Verifier l\'URL. Les URLs ngrok/localhost/IP privee sont malveillantes. Ne pas installer.',

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

  fifo_nc_reverse_shell:
    'CRITIQUE: Reverse shell via mkfifo + netcat detecte. Machine potentiellement compromise. Isoler immediatement. Verifier les connexions sortantes actives.',

  base64_decode_exec:
    'CRITIQUE: Payload encode en base64 pipe vers un shell. Decoder le payload pour analyse: echo "<payload>" | base64 -d. Isoler la machine si deja execute.',

  wget_base64_decode:
    'Telechargement + decodage base64 detecte. Verifier l\'URL de telechargement et decoder le contenu. Pattern de staging malveillant en deux etapes.',

  curl_ifs_evasion:
    'CRITIQUE: Evasion IFS detectee — curl$IFS ou curl${IFS} pipe vers shell. Technique d\'evasion pour contourner la detection de "curl|sh". Ne pas installer.',

  eval_curl_subshell:
    'CRITIQUE: eval $(curl ...) detecte. Telecharge et execute du code distant via command substitution. Ne pas installer.',

  sh_c_curl_exec:
    'sh -c wrapping autour de curl detecte. Technique d\'evasion pour masquer l\'execution de commandes distantes. Analyser le contenu telecharge.',

  python_time_delay_exec:
    'ELEVE: Execution Python avec delai time.sleep() important detectee. ' +
    'Technique d\'evasion sandbox (T1497.003) : le malware attend l\'expiration du timeout sandbox avant d\'executer le payload. ' +
    'Verifier le code Python execute et les connexions reseau post-delai.',

  shai_hulud_backdoor:
    'CRITIQUE: Backdoor Shai-Hulud dans GitHub Actions. Supprimer le workflow et auditer les runs precedents.',

  workflow_injection:
    'Injection potentielle dans GitHub Actions via input non sanitise sur self-hosted runner. Supprimer ou corriger le workflow.',

  workflow_pwn_request:
    'CRITIQUE: Pwn request detecte — pull_request_target avec checkout du head de la PR permet l\'execution de code arbitraire. Remplacer par pull_request ou utiliser une strategie de checkout securisee (base ref uniquement).',

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

  sandbox_timer_delay_suspicious:
    'Timer avec delai > 1h detecte. Possible time-bomb: le malware attend avant de s\'activer pour eviter les sandbox. ' +
    'Verifier le code pour des setTimeout/setInterval avec des delais inhabituels.',

  sandbox_timer_delay_critical:
    'CRITIQUE: Timer avec delai > 24h detecte. Fort indicateur de time-bomb malware. ' +
    'Le package retarde volontairement l\'execution du payload pour echapper a l\'analyse sandbox. ' +
    'NE PAS installer. Analyser le code pour identifier le payload retarde.',

  sandbox_preload_sensitive_read:
    'Lecture de fichiers sensibles detectee via monkey-patching runtime (.npmrc, .ssh, .aws, .env). ' +
    'Le package accede a des credentials pendant l\'installation. Regenerer les secrets exposes.',

  sandbox_network_after_sensitive_read:
    'CRITIQUE: Activite reseau detectee apres lecture de fichiers sensibles. ' +
    'Fort indicateur d\'exfiltration de credentials. Isoler la machine, supprimer le package, ' +
    'regenerer TOUS les secrets. Auditer les connexions reseau recentes.',

  sandbox_exec_suspicious:
    'Execution de commandes dangereuses detectee via monkey-patching runtime (curl, wget, bash, sh, powershell). ' +
    'Verifier les commandes executees. Si le package n\'a pas de raison legitime d\'executer ces commandes, supprimer.',

  sandbox_env_token_access:
    'Acces a des variables d\'environnement sensibles detecte via monkey-patching runtime (TOKEN, SECRET, KEY, PASSWORD). ' +
    'Verifier si le package a une raison legitime d\'acceder a ces variables. Revoquer les credentials si necessaire.',

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

  lifecycle_hidden_payload:
    'CRITIQUE: Le script lifecycle pointe vers un fichier cache dans node_modules/. ' +
    'Ce pattern est utilise par les attaques DPRK/Lazarus pour cacher le payload dans un repertoire ' +
    'que les scanners excluent par defaut. Examiner le fichier cible immediatement.',

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

  crypto_decipher:
    'crypto.createDecipher/createDecipheriv detecte. Dechiffrement de payload embarque a runtime. ' +
    'Pattern canonique de l\'attaque event-stream/flatmap-stream. Extraire et decoder le payload manuellement ' +
    'pour analyser le code execute. Verifier la source des donnees chiffrees.',

  module_compile:
    'CRITIQUE: module._compile() detecte. Cette API Node.js interne execute du code arbitraire ' +
    'a partir d\'une chaine dans le contexte d\'un module. Utilisee dans flatmap-stream pour executer ' +
    'un payload dechiffre sans ecrire sur disque. Isoler immediatement. Analyser la source de la chaine compilee.',

  zlib_inflate_eval:
    'CRITIQUE: Payload obfusque detecte — zlib inflate + decodage base64 + execution dynamique dans le meme fichier. ' +
    'Ce pattern est la signature de la campagne SANDWORM_MODE (fev. 2026). Aucun package legitime ne combine ces 3 elements. ' +
    'Isoler immediatement la machine. Decoder manuellement: zlib.inflateSync(Buffer.from(data, "base64")).toString(). Supprimer le package.',

  module_compile_dynamic:
    'CRITIQUE: Module._compile() avec argument dynamique (variable, expression). Execution de code en memoire ' +
    'sans ecriture sur disque. Technique d\'evasion utilisee dans flatmap-stream et SANDWORM_MODE. ' +
    'Isoler immediatement. Tracer la source de la chaine compilee pour extraire le payload.',

  write_execute_delete:
    'Pattern anti-forensique detecte: ecriture dans un repertoire temporaire (/tmp, /dev/shm, os.tmpdir()), ' +
    'execution via require() ou Module._compile(), puis suppression via unlinkSync/rmSync. ' +
    'Ce pattern de staging est typique des malwares cherchant a eviter la detection post-mortem. ' +
    'Isoler la machine et inspecter les artefacts temporaires avant nettoyage.',

  mcp_config_injection:
    'CRITIQUE: Ecriture dans les fichiers de configuration MCP d\'assistants IA (.claude/, .cursor/, .continue/, .vscode/). ' +
    'Technique SANDWORM_MODE: le malware empoisonne la configuration MCP pour ajouter des serveurs malveillants. ' +
    'Verifier immediatement les fichiers de config IA. Supprimer les entrees MCP non reconnues. Supprimer le package.',

  git_hooks_injection:
    'Injection de hooks Git detectee. Le package ecrit dans .git/hooks/ (pre-commit, pre-push, etc.) ' +
    'ou modifie git config init.templateDir pour la persistence globale. ' +
    'Verifier .git/hooks/ et git config --global --list. Supprimer les hooks non reconnus.',

  env_harvesting_dynamic:
    'Collecte dynamique de variables d\'environnement via Object.entries/keys/values(process.env) ' +
    'avec filtrage par patterns sensibles. Technique de vol de credentials a grande echelle. ' +
    'Verifier les tokens/secrets exposes. Revoquer immediatement les credentials compromis.',

  dns_chunk_exfiltration:
    'Exfiltration via requetes DNS detectee. Les donnees sont encodees en base64 et envoyees comme sous-domaines DNS. ' +
    'Cette technique contourne les firewalls et proxies car le DNS est rarement filtre. ' +
    'Bloquer les requetes DNS sortantes du package. Verifier les donnees exfiltrees.',

  llm_api_key_harvesting:
    'Acces a 3+ cles API de providers LLM (OpenAI, Anthropic, Google, etc.). Usage unique = legitime, ' +
    'acces multiples = collecte pour revente ou abus. Verifier si le package a une raison ' +
    'legitime d\'acceder a plusieurs providers. Revoquer les cles exposees si necessaire.',

  suspicious_domain:
    'Domaine C2 ou d\'exfiltration detecte dans le code source. Ces domaines (oastify.com, webhook.site, ngrok.io, etc.) ' +
    'sont utilises pour recevoir des donnees volees ou relayer des commandes. Verifier si le package a une raison ' +
    'legitime d\'utiliser ce domaine. Bloquer les connexions sortantes vers ce domaine.',

  fetch_decrypt_exec:
    'CRITIQUE: Chaine steganographique detectee. Le code telecharge un fichier distant, le dechiffre via crypto, ' +
    'puis execute le resultat via eval/Function. Pattern buildrunner-dev: payload malveillant cache dans une image PNG. ' +
    'Isoler immediatement. Analyser le payload dechiffre. Supprimer le package.',

  download_exec_binary:
    'CRITIQUE: Pattern download-execute detecte. Le code telecharge un binaire, le rend executable (chmod 755), ' +
    'puis l\'execute via execSync. Dropper deguise en compilation native addon (NeoShadow pattern). ' +
    'Bloquer les telechargements. Verifier les binaires ecrits sur disque. Supprimer le package.',

  ide_persistence:
    'Persistence IDE detectee. Le code ecrit dans tasks.json ou la configuration VS Code avec execution automatique ' +
    'a l\'ouverture du dossier (runOn: folderOpen, reveal: silent). Pattern FAMOUS CHOLLIMA / StegaBin. ' +
    'Verifier ~/.config/Code/User/tasks.json et supprimer les taches inconnues.',

  vm_code_execution:
    'CRITIQUE: Execution de code via le module vm de Node.js. Les methodes vm.runInThisContext(), vm.runInNewContext(), ' +
    'vm.compileFunction() et new vm.Script() permettent d\'executer du code dynamique en contournant la detection eval/Function. ' +
    'Analyser le code source execute. Verifier s\'il s\'agit d\'un moteur de templates ou d\'un payload malveillant.',

  reflect_code_execution:
    'CRITIQUE: Execution de code via l\'API Reflect. Reflect.construct(Function, [...]) et Reflect.apply(eval, ...) ' +
    'contournent la detection directe de eval/new Function(). Technique d\'evasion avancee. ' +
    'Analyser les arguments passes a Reflect. Supprimer le package si non justifie.',

  process_binding_abuse:
    'CRITIQUE: Acces direct aux bindings V8 internes via process.binding() ou process._linkedBinding(). ' +
    'Permet l\'execution de commandes (spawn_sync) ou l\'acces au systeme de fichiers (fs) sans passer par les modules Node.js standards. ' +
    'Technique d\'evasion avancee contournant toute la couche d\'abstraction. Supprimer immediatement.',

  worker_thread_exec:
    'new Worker() avec eval:true detecte. Le code s\'execute dans un thread worker separe, contournant la detection AST du thread principal. ' +
    'Verifier le contenu du code passe au Worker. Si dynamique ou obfusque, supprimer le package. ' +
    'Analyser les communications inter-threads (parentPort, workerData) pour identifier le payload.',

  fragmented_high_entropy_cluster:
    'Cluster de chaines courtes a haute entropie detecte. Possible fragmentation de payload pour eviter la detection. ' +
    'Reconstituer les fragments et analyser le contenu combine. Verifier si les chaines sont concatenees ou reassemblees a l\'execution.',

  wasm_host_sink:
    'CRITIQUE: Module WebAssembly charge avec des imports host contenant des sinks reseau. Le flux de controle est cache dans le binaire WASM, ' +
    'rendant l\'analyse statique impossible. Le WASM peut lire des fichiers sensibles et exfiltrer via les callbacks host. ' +
    'Supprimer le package immediatement. Analyser le fichier WASM avec wasm2wat pour comprendre le flux. Regenerer tous les secrets.',
  wasm_standalone:
    'Module WebAssembly charge sans sink reseau apparent. Usage potentiellement legitime (crypto, image, codecs video). ' +
    'Verifier le fichier .wasm avec wasm2wat. Si le package n\'a aucune raison d\'utiliser du WASM, considerer comme suspect.',
  credential_regex_harvest:
    'Code contient des regex de detection de credentials (Bearer, password, token, API key) combine avec un appel reseau. ' +
    'Technique de harvesting: scanne les donnees en transit (streams HTTP, fichiers) pour extraire des secrets et les exfiltrer. ' +
    'Supprimer le package. Auditer le trafic reseau sortant.',
  builtin_override_exfil:
    'Code remplace une methode built-in (console.log/warn/error, Object.defineProperty) et contient un appel reseau. ' +
    'Technique de monkey-patching: intercepte les donnees passant par les APIs natives pour les exfiltrer. ' +
    'Supprimer le package. Verifier si d\'autres methodes natives ont ete modifiees.',
  stream_credential_intercept:
    'Classe stream (Transform/Duplex/Writable) avec regex de credentials et appel reseau. ' +
    'Technique de wiretap: le stream intercepte les donnees en transit, scanne pour des secrets (Bearer, password, token) ' +
    'et les exfiltre via un appel reseau. Supprimer le package.',
  remote_code_load:
    'CRITIQUE: Fetch reseau + eval/new Function() dans le meme fichier. ' +
    'Technique multi-stage: le package telecharge un payload depuis un serveur distant (SVG, HTML, JSON) puis l\'execute. ' +
    'Supprimer le package. Bloquer le domaine C2 au niveau firewall.',
  proxy_data_intercept:
    'CRITIQUE: Un Proxy JavaScript avec trap set/get/apply est combine avec un appel reseau. ' +
    'Technique d\'interception: le Proxy capture toutes les ecritures de proprietes (credentials, tokens, config) ' +
    'et les exfiltre via HTTPS/fetch/dgram. Supprimer le package. Auditer tous les modules qui importent ce package.',
  proxy_globalthis_intercept:
    'CRITIQUE: new Proxy(globalThis/global) intercepte tous les acces au scope global. ' +
    'L\'attaquant peut hooker eval, Function, require de maniere transparente via le handler Proxy. ' +
    'Supprimer le package immediatement.',
  reflect_bind_code_execution:
    'CRITIQUE: Reflect.apply() avec methode prototype (bind/call/apply) et thisArg=Function/eval. ' +
    'Evasion de 2nd niveau contournant la detection Reflect.apply(eval). Supprimer le package.',
  detached_credential_exfil:
    'CRITIQUE: Process detache avec acces aux credentials et exfiltration reseau. ' +
    'Technique DPRK/Lazarus: le process fils survit au parent (detached:true, unref()) et exfiltre des secrets en arriere-plan. ' +
    'Supprimer le package immediatement. Regenerer tous les tokens/credentials. Auditer les process en cours d\'execution.',
  intent_credential_exfil:
    'CRITIQUE: Coherence d\'intention detectee — lecture de credentials combinee avec exfiltration reseau. ' +
    'Pattern multi-fichier DPRK/Lazarus: chaque fichier semble legitime individuellement mais le package ' +
    'dans son ensemble collecte des secrets et les envoie sur le reseau. Supprimer le package immediatement. ' +
    'Regenerer tous les tokens/credentials exposes. Auditer le package.json pour les scripts lifecycle.',
  intent_command_exfil:
    'Coherence d\'intention detectee — sortie de commande systeme combinee avec exfiltration reseau. ' +
    'Le package execute des commandes et transmet les resultats. Verifier les commandes executees. ' +
    'Supprimer le package si non attendu. Auditer les logs reseau pour identifier les donnees exfiltrees.',

  unicode_invisible_injection:
    'CRITIQUE: Caracteres Unicode invisibles detectes (zero-width, variation selectors). ' +
    'Technique GlassWorm: du code malveillant est encode via des variation selectors invisibles dans les editeurs. ' +
    'Analyser le fichier avec un editeur hexa. Supprimer le package immediatement. ' +
    'Verifier les autres fichiers du projet pour des injections similaires.',

  unicode_variation_decoder:
    'CRITIQUE: Decodeur de payload Unicode via variation selectors detecte (.codePointAt + 0xFE00/0xE0100). ' +
    'Signature GlassWorm: le code reconstruit un payload octet par octet a partir de caracteres invisibles. ' +
    'Isoler immediatement. Decoder manuellement les variation selectors pour extraire le payload. Supprimer le package.',

  blockchain_c2_resolution:
    'Import Solana/Web3 + appel API blockchain C2 (getSignaturesForAddress, getTransaction) detecte. ' +
    'Technique GlassWorm: la blockchain sert de dead drop resolver pour obtenir l\'adresse C2 via le champ memo. ' +
    'Cout de rotation: 0.000005 SOL par changement d\'adresse C2 — censorship-resistant. ' +
    'Bloquer les connexions vers les RPC Solana. Supprimer le package.',

  dangerous_constructor:
    'CRITIQUE: Acces au constructeur AsyncFunction/GeneratorFunction via Object.getPrototypeOf(). ' +
    'Technique d\'evasion avancee: le constructeur n\'est pas accessible directement comme eval() ou Function(), ' +
    'mais peut etre obtenu via la chaine prototype. Permet l\'execution de code arbitraire asynchrone. ' +
    'Supprimer le package immediatement. Auditer le code genere dynamiquement.',

  module_load_bypass:
    'CRITIQUE: Module._load() detecte — bypass du module loader interne de Node.js. ' +
    'Permet de charger dynamiquement des modules (child_process, fs, net) sans passer par require(), ' +
    'contournant les restrictions et les hooks de chargement. ' +
    'Supprimer le package immediatement. Auditer les modules charges dynamiquement.',

  split_entropy_payload:
    'CRITIQUE: Payload haute entropie fragmente en ≥3 chunks concatenes pour contourner la detection. ' +
    'Le resultat concatene est passe a eval/Function/atob/Buffer.from, indiquant un dechiffrement ou une execution staged. ' +
    'Technique d\'evasion: chaque chunk individuel a une entropie basse, mais la concatenation revele le payload. ' +
    'Supprimer le package immediatement. Analyser le payload decode dans un sandbox.',

  blockchain_rpc_endpoint:
    'Endpoint RPC blockchain hardcode detecte (Solana mainnet, Infura Ethereum). ' +
    'Dans un package non-crypto, cela indique un potentiel canal C2 via blockchain. ' +
    'Verifier le contexte: si le package n\'a rien a voir avec la blockchain, supprimer immediatement.',

  crypto_staged_payload:
    'CRITIQUE: Chaine steganographique complete detectee — fichier binaire (.png/.jpg/.wasm) avec eval() + dechiffrement crypto. ' +
    'Le payload malveillant est cache dans un fichier binaire et dechiffre a runtime. Supprimer le package immediatement. ' +
    'Analyser le fichier binaire dans un sandbox pour extraire le payload.',

  lifecycle_typosquat:
    'CRITIQUE: Package avec nom similaire a un package populaire ET scripts lifecycle. ' +
    'Vecteur classique de dependency confusion: le code s\'execute a l\'installation. ' +
    'NE PAS installer. Verifier le nom exact du package. Signaler sur npm.',

  lifecycle_inline_exec:
    'CRITIQUE: Script lifecycle avec node -e (execution inline). Le code s\'execute automatiquement a npm install. ' +
    'NE PAS installer. Si deja installe: considerer la machine compromise. ' +
    'Auditer les modifications systeme recentes.',

  lifecycle_remote_require:
    'CRITIQUE: Script lifecycle avec require(http/https) pour charger du code distant. ' +
    'Le payload est telecharge et execute automatiquement a l\'installation. ' +
    'NE PAS installer. Bloquer les connexions sortantes. Supprimer le package.',

  lifecycle_file_exec:
    'CRITIQUE: Un script lifecycle (preinstall/postinstall) execute un fichier JS contenant des menaces HIGH/CRITICAL. ' +
    'Le malware est cache derriere une indirection: package.json → node setup.js → payload malveillant. ' +
    'NE PAS installer. Supprimer le package immediatement. Auditer le fichier reference.',

  uncaught_exception_exfil:
    'CRITIQUE: Exfiltration silencieuse via process.on("uncaughtException"). ' +
    'Le handler intercepte les erreurs pour envoyer les credentials (process.env) a un serveur externe. ' +
    'Regenerer immediatement tous les secrets. Supprimer le package. Auditer les connexions sortantes.',

  websocket_credential_exfil:
    'CRITIQUE: Exfiltration de credentials via canal non-HTTP (WebSocket, MQTT, Socket.io). ' +
    'Les proxies HTTP ne detectent pas ce trafic. Regenerer immediatement tous les secrets exposes. ' +
    'Bloquer les connexions sortantes sur les ports non-HTTP. Supprimer le package.',

  lifecycle_dataflow:
    'CRITIQUE: Script lifecycle (preinstall/postinstall) combine avec un flux de donnees suspect. ' +
    'Le package lit des credentials et les envoie via le reseau a l\'installation. ' +
    'NE PAS installer. Regenerer les secrets. Supprimer le package immediatement.',

  lifecycle_dangerous_exec:
    'CRITIQUE: Script lifecycle combine avec execution de commande shell dangereuse. ' +
    'Le package execute des commandes systeme arbitraires a l\'installation (curl, wget, nc, bash). ' +
    'NE PAS installer. Bloquer les connexions sortantes. Supprimer le package immediatement.',

  obfuscated_lifecycle_env:
    'CRITIQUE: Code obfusque + acces aux variables d\'environnement + script lifecycle. ' +
    'Triple signal d\'exfiltration install-time: le code est masque pour voler des credentials. ' +
    'NE PAS installer. Regenerer tous les secrets. Supprimer le package immediatement.',

  suspicious_module_sink:
    'Module reseau non-HTTP (ws, mqtt, socket.io) utilise comme sink de donnees. ' +
    'Verifier si des donnees sensibles sont envoyees via ce canal. ' +
    'Les proxies HTTP classiques ne filtrent pas ce trafic.',

  bin_field_hijack:
    'CRITIQUE: Le champ "bin" de package.json shadow une commande systeme (node, npm, git, bash, etc.). ' +
    'A l\'installation, npm cree un symlink dans node_modules/.bin/ qui intercepte la commande reelle. ' +
    'Tous les npm scripts executeront le code malveillant au lieu de la vraie commande. ' +
    'NE PAS installer. Si deja installe: rm -rf node_modules && npm cache clean --force && npm install.',

  git_dependency_rce:
    'Dependance utilisant une URL git+ ou git://. Vecteur d\'attaque PackageGate: si le package contient ' +
    'un .npmrc avec git=./malicious.sh, npm executera le script au lieu de git, meme avec --ignore-scripts. ' +
    'Verifier le contenu du .npmrc. Ne pas installer de packages avec des dependances git non vérifiées.',

  npmrc_git_override:
    'CRITIQUE: Fichier .npmrc contient git= override — technique PackageGate. Le binaire git est remplace ' +
    'par un script controle par l\'attaquant. TOUTE operation git (clone, fetch, pull) executera le script malveillant. ' +
    'NE PAS installer. Si deja installe: supprimer le package, verifier .npmrc, reinstaller git.',

  node_modules_write:
    'CRITIQUE: Le code ecrit dans node_modules/ — technique de propagation worm Shai-Hulud 2.0. ' +
    'Le malware modifie d\'autres packages installes (ethers, webpack, etc.) pour injecter un backdoor persistent. ' +
    'Verifier l\'integrite de tous les packages: rm -rf node_modules && npm install. ' +
    'Auditer les fichiers modifies. Regenerer tous les secrets si le code a ete execute.',

  bun_runtime_evasion:
    'Invocation du runtime Bun detectee — technique Shai-Hulud 2.0. Le payload est execute via bun run ' +
    'au lieu de node, echappant a toutes les sandboxes Node.js et au monitoring (--experimental-permission). ' +
    'Verifier si bun est installe: which bun. Supprimer le package. ' +
    'Auditer les processus: ps aux | grep bun.',

  static_timer_bomb:
    'Timer avec delai > 1h detecte dans l\'analyse statique (setTimeout/setInterval). ' +
    'Technique PhantomRaven: le payload s\'active 48h+ apres l\'installation pour echapper aux sandboxes. ' +
    'Analyser le callback du timer pour identifier le payload retarde. ' +
    'Si delai > 24h: fort indicateur de time-bomb malware. NE PAS installer.',

  npm_publish_worm:
    'CRITIQUE: exec("npm publish") detecte — propagation worm. Le code utilise des tokens npm voles ' +
    'pour publier des versions infectees des packages de la victime. Technique Shai-Hulud 1.0 et 2.0. ' +
    'Isoler immediatement la machine. Revoquer les tokens npm: npm token revoke. ' +
    'Verifier les packages publies: npm profile ls. Signaler sur npm.',

  systemd_persistence:
    'CRITIQUE: Ecriture dans un chemin systemd ou execution de systemctl enable/start. ' +
    'Pattern CanisterWorm (pgmon.service) et TeamPCP (sysmon.service). ' +
    'Aucun package npm legitime ne cree de services systemd. ' +
    'Verifier: systemctl --user list-units | grep pgmon. ' +
    'Supprimer: systemctl --user stop pgmon && rm ~/.config/systemd/user/pgmon.service. ' +
    'Inspecter ~/.local/share/pgmon/ pour les payloads.',

  npm_token_steal:
    'CRITIQUE: exec("npm config get _authToken") ou exec("npm whoami") detecte. ' +
    'Extraction programmatique de credentials npm — pattern findNpmTokens() de CanisterWorm. ' +
    'Le token vole sera utilise pour publier des versions infectees de vos packages. ' +
    'Revoquer immediatement: npm token revoke <token>. Verifier les publications recentes.',

  root_filesystem_wipe:
    'CRITIQUE: rm -rf / detecte — suppression totale du systeme de fichiers. ' +
    'Pattern kamikaze.sh du wiper CanisterWorm ciblant les systemes Iran (Asia/Tehran). ' +
    'NE PAS executer. Isoler immediatement. Signaler comme destructware.',

  proc_mem_scan:
    'CRITIQUE: Acces a /proc/*/mem — extraction de secrets depuis la memoire des processus. ' +
    'Technique TeamPCP credential stealer dans Trivy v0.69.4. ' +
    'Scanne les processus CI runner pour extraire les secrets GitHub Actions. ' +
    'Verifier que Trivy est en version >= 0.69.5. Rotation immediate de tous les secrets CI/CD.',

  ollama_local_llm:
    'Reference au port Ollama (11434) detectee. PhantomRaven Wave 4 utilise un LLM local (DeepSeek Coder) ' +
    'pour reecrire le malware a chaque execution, evitant la detection par signature. Moteur polymorphe. ' +
    'Verifier si Ollama est installe: curl http://localhost:11434/api/tags. ' +
    'Aucun package npm legitime n\'appelle un LLM local. Supprimer le package.',

  pth_persistence:
    'CRITIQUE: Ecriture d\'un fichier .pth detectee. Les fichiers .pth dans site-packages/ sont executes ' +
    'automatiquement par Python au demarrage — c\'est un vecteur de persistence invisible. ' +
    'Technique LiteLLM/Checkmarx (mars 2026): litellm_init.pth contient du code base64 qui installe un stealer ' +
    'dans ~/.config/sysmon/ et exfiltre vers checkmarx.zone. ' +
    'Verifier: find $(python -c "import site; print(site.getsitepackages()[0])") -name "*.pth" -exec cat {} \\; ' +
    'Supprimer tout fichier .pth non standard. Rotation des credentials.',

  // Audit v3 Bypass Playbooks (AST-062 to AST-069)
  reflect_apply_require:
    'CRITIQUE: Reflect.apply(require, null, [module]) detecte — contournement de require() via Reflect API. ' +
    'Aucun package legitime ne charge des modules via Reflect.apply. ' +
    'Supprimer le package. Auditer les modules charges dynamiquement.',

  finalization_registry_exec:
    'CRITIQUE: FinalizationRegistry avec callback dangereux (child_process/exec/spawn). ' +
    'Le callback s\'execute apres le garbage collection, hors du flux synchrone — evasion sandbox. ' +
    'Aucun usage legitime ne combine FinalizationRegistry avec des appels systeme. Supprimer le package.',

  function_prototype_constructor:
    'CRITIQUE: Acces au constructeur Function via chaine de prototypes — (function(){}).constructor(code) ' +
    'ou [].constructor.constructor(code). Equivalent a eval() mais invisible aux detections statiques de eval/Function. ' +
    'Supprimer le package. Aucun usage legitime.',

  prototype_pollution:
    'HAUTE: Pollution de prototype detectee (__proto__, __defineGetter__, __defineSetter__). ' +
    'Peut detourner les proprietes heritees de tous les objets du runtime. ' +
    'Verifier si le code modifie Object.prototype ou des prototypes de classes natives. ' +
    'Si combine avec du code d\'execution dynamique, traiter comme CRITIQUE.',

  module_wrap_override:
    'CRITIQUE: Module.wrap remplace — la fonction wrapper du module loader est detournee. ' +
    'Tout module charge apres cette modification execute du code injecte. ' +
    'Aucun package legitime ne remplace Module.wrap. Supprimer immediatement.',

  symbol_property_hiding:
    'HAUTE: Module dangereux cache derriere une propriete Symbol. ' +
    'Invisible a Object.keys(), JSON.stringify() et for...in. Technique anti-forensics. ' +
    'Auditer toutes les proprietes Symbol du module. Supprimer si combine avec child_process/fs.',

  with_body_dangerous:
    'HAUTE: with() statement avec require/exec/spawn dans le body. ' +
    'Le with() rend les identifiants ambigus, empechant l\'analyse statique. ' +
    'Aucun code moderne legitime n\'utilise with(). Supprimer le package.',

  require_process_mainmodule:
    'CRITIQUE: require("process").mainModule.require() detecte — contournement de la detection ' +
    'process.mainModule.require() via require("process") au lieu de l\'objet global. ' +
    'Aucun package legitime n\'utilise ce pattern. Supprimer immediatement.',

  // Blue Team v8 — New playbook entries
  shared_memory_ipc:
    'SharedArrayBuffer + Worker Thread detectes. Canal IPC memoire partagee qui contourne la surveillance. ' +
    'Verifier si les workers manipulent des donnees sensibles. Isoler si combine avec eval/exec.',

  websocket_c2:
    'HAUTE: Connexion WebSocket vers domaine suspect ou avec execution dynamique. Canal C2 persistant bidirectionnel. ' +
    'Analyser l\'URL de connexion. Bloquer les connexions WebSocket sortantes. Verifier les messages echanges.',

  udp_exfiltration:
    'HAUTE: Socket UDP (dgram) avec envoi de donnees. Exfiltration contournant les firewalls HTTP. ' +
    'Verifier les destinations IP. Bloquer le trafic UDP sortant non-DNS. Auditer les donnees envoyees.',

  native_addon_install:
    'HAUTE: binding.gyp avec script lifecycle non-standard. Code natif compile a l\'installation. ' +
    'Verifier le contenu de binding.gyp et les sources C/C++. Installer avec --ignore-scripts si suspect.',

  string_mutation_obfuscation:
    'HAUTE: Chaine de .replace() reconstruisant des noms d\'API dangereuses (leet-speak). ' +
    'Technique d\'evasion par substitution de caracteres. Decoder la chaine finale. Supprimer si malveillant.',

  crontab_systemd_write:
    'CRITIQUE: Ecriture dans les fichiers cron/crontab. Persistence via tache planifiee. ' +
    'Verifier /etc/cron*, /var/spool/cron. Supprimer les entrees ajoutees. Auditer crontab -l.',

  isolated_suspicious_file:
    'Un seul fichier suspect parmi de nombreux fichiers propres. Pattern de dissimulation typique ' +
    'ou le code malveillant est cache dans un package apparemment legitime. Examiner le fichier suspect en detail.',

  deep_suspicious_file:
    'Pattern suspect dans un fichier profondement imbrique. Technique pour echapper aux analyses superficielles. ' +
    'Verifier le contenu du fichier et son role dans l\'arborescence du package.',

  // Blue Team v8b playbooks
  module_internals_hijack:
    'CRITIQUE: Assignation a Module._resolveFilename/_compile/_extensions. Detournement du systeme de modules Node.js. ' +
    'Tous les require() sont interceptes. Supprimer le package immediatement. Auditer tous les modules charges apres installation.',

  json_reviver_pollution:
    'HAUTE: JSON.parse avec reviver accedant a __proto__/prototype. Pollution de prototype via JSON. ' +
    'Ne jamais passer de JSON non fiable avec un reviver manipulant __proto__. Verifier les sources de donnees JSON.',

  vm_dynamic_code:
    'CRITIQUE: vm.runInContext/compileFunction avec code construit dynamiquement. Evasion de sandbox. ' +
    'Verifier d\'ou provient le code execute. Bloquer l\'acces au module vm. Supprimer si non justifie.',

  callback_exec_rce:
    'CRITIQUE: exec/spawn dans callback .on(\'message\'|\'data\'). Execution de commandes depuis flux reseau. ' +
    'Pattern C2: commandes recues par WebSocket/TCP executees via child_process. Supprimer immediatement.',

  stego_binary_exec:
    'CRITIQUE: Lecture de fichier image/binaire + eval/Function. Payload steganographique. ' +
    'Verifier le contenu du fichier image. Scanner avec des outils stego. Supprimer le fichier et le code d\'extraction.',

  asynclocal_context_exec:
    'HAUTE: AsyncLocalStorage + execution dynamique. Code malveillant cache dans un contexte async. ' +
    'Examiner les callbacks AsyncLocalStorage. Verifier ce qui est stocke et execute dans le store.',

  prototype_chain_constructor:
    'CRITIQUE: Object.getPrototypeOf(var).constructor stocke dans une variable. Traversee de prototype pour Function. ' +
    'Technique d\'evasion avancee. Supprimer le code. Verifier si le constructeur est appele avec du code dynamique.',

  ci_environment_probe:
    'HAUTE: Detection de 3+ fournisseurs CI (GitHub Actions, GitLab CI, etc.) dans le meme fichier. ' +
    'Sondage d\'environnement CI pour activation conditionnelle. Verifier la logique conditionnelle associee.',

  lifecycle_missing_script:
    'CRITIQUE: Script lifecycle reference un fichier inexistant dans le package. Script fantome. ' +
    'Le payload peut etre injecte dynamiquement ou lors d\'une mise a jour. Installer avec --ignore-scripts. Supprimer le package.',
};

function getPlaybook(threatType) {
  return PLAYBOOKS[threatType] || 'Analyser manuellement cette menace.';
}

module.exports = { getPlaybook, PLAYBOOKS };