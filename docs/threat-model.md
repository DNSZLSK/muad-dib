# MUAD'DIB Threat Model

## Ce que MUAD'DIB detecte

### Attaques Supply Chain npm & PyPI

| Technique | Detection | Confidence |
|-----------|-----------|------------|
| Packages malveillants connus (npm) | Hash SHA256 + nom | HIGH |
| Shai-Hulud v1/v2/v3 | Marqueurs + fichiers + comportements | HIGH |
| event-stream (2018) | Nom + version | HIGH |
| Typosquatting npm | Liste de packages connus | MEDIUM |
| Protestware (node-ipc, colors) | Nom + version | HIGH |
| Packages malveillants PyPI (14K+ depuis OSV dump) | Correspondance par nom | HIGH |
| Typosquatting PyPI | Levenshtein + normalisation PEP 503 | MEDIUM |

### Comportements malveillants

| Technique | Detection | Confidence |
|-----------|-----------|------------|
| Vol de credentials (.npmrc, .ssh) | Analyse AST | HIGH |
| Exfiltration via env vars (GITHUB_TOKEN) | Analyse AST | HIGH |
| Execution de code distant (curl \| sh) | Pattern matching | HIGH |
| Reverse shell | Pattern matching | HIGH |
| Dead man's switch (rm -rf $HOME) | Pattern matching | HIGH |
| Code obfusque | Heuristiques | MEDIUM |
| Chaines haute entropie (base64, hex, chiffre) | Analyse entropie Shannon | MEDIUM |

### Flux de donnees suspects

| Technique | Detection | Confidence |
|-----------|-----------|------------|
| Lecture credential + envoi reseau | Analyse dataflow | HIGH |
| Acces process.env + fetch/request | Analyse dataflow | HIGH |

### Detection des malwares CI-aware (v2.1.2)

Certains malwares supply-chain ne s'activent que dans un environnement CI/CD. Ils testent la presence de variables comme `CI`, `GITHUB_ACTIONS`, `GITLAB_CI` avant d'executer leur payload, restant dormants sur les machines locales.

Le sandbox MUAD'DIB simule 6 environnements CI : GitHub Actions, GitLab CI, Travis CI, CircleCI, Jenkins. Les malwares CI-aware declenchent leur payload dans le container isole, permettant leur detection via strace, tcpdump et filesystem diff.

### Canary tokens / Honey tokens (v2.1.2)

Le sandbox injecte 6 faux credentials comme honeypots :

| Token | Type | Objectif |
|-------|------|----------|
| GITHUB_TOKEN | Registry token | Detecter vol de tokens GitHub |
| NPM_TOKEN | Registry token | Detecter vol de tokens npm |
| AWS_ACCESS_KEY_ID | Cloud credential | Detecter vol de cles AWS |
| AWS_SECRET_ACCESS_KEY | Cloud credential | Detecter vol de secrets AWS |
| SLACK_WEBHOOK_URL | Messaging webhook | Detecter exfiltration Slack |
| DISCORD_WEBHOOK_URL | Messaging webhook | Detecter exfiltration Discord |

**Detection double couche** :
1. **Tokens dynamiques** : Suffixe aleatoire genere par `canary-tokens.js` a chaque session, injecte via Docker `-e`
2. **Tokens statiques** : Valeurs fallback dans `sandbox-runner.sh`, detectes par `detectStaticCanaryExfiltration()` dans `sandbox.js`

**7 vecteurs de detection** :
- Corps HTTP (POST bodies)
- Requetes DNS (tunneling DNS)
- URLs de requetes HTTP
- Connexions TLS (SNI)
- Modifications filesystem (fichiers crees)
- Commandes processus (arguments)
- Sortie d'installation npm (stdout/stderr)

Si un package tente d'exfiltrer un canary token, c'est la preuve directe de comportement malveillant (CRITICAL, +50 au score, regle MUADDIB-CANARY-001).

## Ce que MUAD'DIB NE detecte PAS

### Attaques browser-only (hors scope)

MUAD'DIB est un analyseur statique Node.js. Les attaques qui utilisent exclusivement des APIs browser (DOM, `document`, `window`, `XMLHttpRequest`) sans aucune API Node.js ne sont pas detectees. Ces 4 samples du ground truth sont documentes comme hors scope :

| Sample | Technique | Raison de non-detection |
|--------|-----------|------------------------|
| **lottie-player** | `document.createElement('script')` injection | API DOM browser, aucune API Node.js |
| **polyfill-io** | Injection de script via CDN browser | Modification de ressources CDN cote client, pas de code Node.js malveillant |
| **trojanized-jquery** | Manipulation DOM jQuery | API jQuery/DOM browser, aucune API Node.js |
| **websocket-rat** | `exec(variable)` via WebSocket | API Node.js presente mais `exec(variable)` est trop generique — detecter ce pattern causerait des faux positifs sur du code legitime |

Impact sur TPR : 46/49 = 93.9% (3 misses documentes et acceptes). Note : websocket-rat est desormais detecte depuis v2.5.16.

### Limitations connues

| Technique | Raison |
|-----------|--------|
| Malware polymorphe avance | Pas de ML/machine learning, patterns statiques uniquement |
| Obfuscation avancee | Desobfuscation statique (v2.2.5) couvre concat, charcode, base64, hex arrays + const propagation. Les obfuscateurs avances (JScrambler, control flow flattening) ne sont pas couverts |
| Zero-day (packages inconnus) | Base IOC reactive (v1.x); atténué par la détection comportementale (v2.0) et validé par le ground truth (v2.1) |
| Attaques via binaires natifs | Pas d'analyse binaire |
| Backdoors subtiles | Pas de review de code semantique |
| Time bombs (declenchement differe) | Pas d'analyse temporelle |
| Contenu TLS chiffre | Capture SNI et correlation DNS/TLS, mais pas d'interception MITM |
| Ecosystemes non supportes | Limite a npm et PyPI (pas RubyGems, Maven, Go) |
| Dashboard/API cloud | Outil CLI local uniquement |

### Faux negatifs potentiels

- Code malveillant dans des fichiers non-JS/non-Python (WASM, binaires)
- Exfiltration via canaux couverts (DNS tunneling, steganographie)
- Malware qui detecte l'environnement d'analyse (anti-sandbox)
- Attaques multi-etapes avec payload distant
- Obfuscation JS avancee non couverte par les heuristiques

## Protections de securite internes

### Sanitization des inputs

| Protection | Detail |
|------------|--------|
| YAML safe schema | Tous les appels `yaml.load()` utilisent `{ schema: yaml.JSON_SCHEMA }` pour bloquer les tags dangereux (`!!js/function`, `!!python/object`) |
| Git ref sanitization | Les references git (tags, branches, commits) passees a `muaddib diff` sont validees contre l'injection de commande avant execution de `git checkout` |
| CLI argument validation | Les arguments CLI de longueur excessive (>10000 chars), les paths unicode, et les tentatives d'injection shell (`$(...)`, backticks) sont neutralises |

### Securite reseau

| Protection | Detail |
|------------|--------|
| SSRF protection | Download centralise dans `src/shared/download.js` : whitelist de domaines registres (registry.npmjs.org, pypi.org, etc.), blocage des IP privees (127.x, 10.x, 172.16-31.x, 192.168.x, 169.254.x, IPv6 loopback/link-local), validation des redirections |
| Webhook timeout | Les envois webhook (Discord/Slack) sont limites en temps pour eviter les blocages sur des endpoints lents ou malveillants |
| Webhook strict | Alertes uniquement pour IOC match, sandbox confirm, ou canary exfiltration (pas de heuristiques basse confiance) |
| Fail-closed sur registry | Si le registre npm est injoignable lors d'un `muaddib install`, l'installation echoue par defaut plutot que de continuer sans verification. `safe-install` bloque egalement si la base IOC est indisponible (design fail-closed) |

### Securite des installations

| Protection | Detail |
|------------|--------|
| `--ignore-scripts` | Les `npm install` internes (sandbox, safe-install) utilisent le flag `--ignore-scripts` pour empecher l'execution de preinstall/postinstall malveillants |
| Symlink protection | `lstatSync` est utilise pour detecter les liens symboliques et eviter les boucles infinies ou l'acces a des fichiers hors scope |
| XSS dans rapports HTML | Les donnees utilisateur dans les rapports HTML sont echappees via `escapeHtml()` |
| Docker sandbox (analyse dynamique) | L'analyse sandbox valide le nom du package via `sanitizePackageName()` avant passage au container Docker |
| Command injection prevention | `execFileSync` avec arguments en tableau au lieu de `execSync` avec template literals pour l'extraction tar. `NPM_PACKAGE_REGEX` centralise dans `src/shared/constants.js` |
| Path traversal prevention | `sanitizePackageName()` supprime les sequences `..` dans les noms de packages |

## Resultats des tests adversariaux

### Taux de detection : 77/78 (98.7% ADR)

78 samples adversariaux/holdout evasifs (38 adversariaux + 40 holdouts sur 5 vagues red team) testes avec des techniques d'evasion reelles (obfuscation, dataflow inter-module, charcode reconstruction, prototype hooking, AI agent weaponization, etc.). 1 miss documente : `require-cache-poison` (compromis accepte avec la reduction FP P3).

Voir [Evaluation Methodology](EVALUATION_METHODOLOGY.md) pour le detail des scores pre-tuning et post-tuning.

### Robustesse (56 fuzz tests)

Les parsers ont ete testes avec des inputs malformes :
- **YAML** : invalide, `!!js/function` bloque, vide, 10MB, unicode, null bytes, billion laughs, nesting 100 niveaux
- **JSON** : invalide, vide, cles 10000 chars, valeurs null, types incorrects, 10000 deps, prototype pollution
- **AST** : syntaxe invalide, binaire en .js, vide, commentaires seuls, null bytes, BOM, 100 niveaux de callbacks
- **CLI** : arguments 10000 chars, paths unicode, injection shell `$(...)`, flags conflictuels

Resultat : **56/56 pass**. Aucun crash, aucune exception non rattrapee.

### 1317 tests unitaires et d'integration

Couverture complete des scanners, parsers, IOC matching, typosquatting, integrations CLI, diff, monitor, temporal analysis, ground truth, canary tokens, et securite (SSRF, injection). 86% code coverage (c8).

### Validation Ground Truth (v2.2.12)

51 attaques supply-chain reelles sont rejouees automatiquement pour valider la couverture. La base inclut event-stream, ua-parser-js, coa, node-ipc, colors, eslint-scope, flatmap-stream, solana-web3js, rc, getcookies, ledgerhq-connect-kit, shai-hulud, et 39 autres attaques de 2018 a 2025.

Taux de detection : **93.9%** (46/49 attaques actives). 3 misses documentes comme hors scope (voir section "Attaques browser-only" ci-dessus).

### Benchmark Datadog 17K (v2.3.1)

Validation a grande echelle contre le [DataDog Malicious Software Packages Dataset](https://github.com/DataDog/malicious-software-packages-dataset) : 17 922 packages malveillants npm reels.

- **TPR brut : 88.2%** (15 810 / 17 922)
- **TPR ajuste (malware JS/Node.js) : ~100%** (15 810 / ~15 845)

Les 2 077 misses (score=0) ont ete categorises manuellement :
- **1 233 pages de phishing** : HTML/CSS/JS frontend (faux login, redirects, captchas). Aucune API Node.js (`require`, `child_process`, `fs`, `process.env`).
- **824 binaires natifs** : Pas de fichiers JS. 201 packages @42ailab (binaires multi-plateforme darwin-arm64, linux-x64, etc.) + 623 autres.
- **20 bibliotheques corrigees** : Code malveillant retire avant le scan (compromission temporaire).

Limitation connue et documentee : MUAD'DIB fait de l'analyse AST statique Node.js. La detection de phishing HTML et l'analyse de binaires natifs sont hors scope.

### Suivi du taux de faux positifs (v2.1)

Le systeme de FP rate tracking (`muaddib stats`) enregistre quotidiennement :
- Nombre total de packages scannes
- Clean / Suspect / Faux positif / Confirme malveillant
- Taux de faux positifs = FP / (FP + Confirme)
- Ventilation par jour (`--daily`)

### Metriques de temps de detection (v2.1)

Le systeme de detection time logging (`muaddib detections`) suit :
- `first_seen_at` : timestamp de premiere detection par MUAD'DIB
- `advisory_at` : timestamp de l'advisory publique (OSV, GitHub Advisory, etc.)
- `lead_time_hours` : delai entre detection et advisory (en heures)
- Statistiques agregees : count, avg, min, max du lead time

## Hypotheses

1. **Le code source est disponible** - MUAD'DIB analyse le code JS et les dependances Python, pas les binaires
2. **Les IOCs sont a jour** - La detection depend de la base IOC
3. **L'attaquant utilise des techniques connues** - Zero-days passent a travers
4. **Le scan est execute avant l'installation** - Apres `npm install`, c'est trop tard si preinstall a execute

## Architecture de detection
```
┌─────────────────────────────────────────────────────────────┐
│                      MUAD'DIB Scanner                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  IOC Match  │  │  AST Parse  │  │  Pattern Matching   │  │
│  │  (hashes,   │  │  (acorn)    │  │  (shell, scripts)   │  │
│  │  packages)  │  │             │  │                     │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         │                │                     │             │
│         v                v                     v             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                   Dataflow Analysis                      ││
│  │            (credential read -> network send)             ││
│  └─────────────────────────────────────────────────────────┘│
│         │                │                     │             │
│         v                v                     v             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                  Python Scanner                           ││
│  │  (requirements.txt, setup.py, pyproject.toml, PyPI IOC)  ││
│  └─────────────────────────────────────────────────────────┘│
│         │                │                     │             │
│         v                v                     v             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                   Threat Enrichment                      ││
│  │         (rules, MITRE ATT&CK, playbooks)                 ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## Mapping MITRE ATT&CK

| Technique | ID | Detection MUAD'DIB |
|-----------|----|--------------------|
| Credentials in Files | T1552.001 | AST analysis |
| Private Keys (.ssh/id_rsa) | T1552.004 | AST analysis |
| Command and Scripting Interpreter | T1059 | Pattern matching |
| Unix Shell (reverse shell, netcat) | T1059.004 | Pattern matching |
| JavaScript (eval, new Function) | T1059.007 | AST analysis |
| Application Layer Protocol (DNS/HTTP) | T1071 | Sandbox dynamic analysis (network capture) |
| Supply Chain Compromise (npm) | T1195.002 | IOC matching |
| PyPI Supply Chain Compromise | T1195.002 | IOC matching |
| PyPI Typosquatting | T1195.002 | Levenshtein + PEP 503 |
| Obfuscated Files | T1027 | Heuristics |
| Shannon Entropy (strings/files) | T1027 | Entropy analysis |
| Exfiltration Over C2 Channel | T1041 | Dataflow analysis |
| Data Destruction | T1485 | Pattern matching |
| Ingress Tool Transfer | T1105 | Pattern matching |
| Endpoint Denial of Service | T1499 | Sandbox dynamic analysis (timeout detection) |
| Create or Modify System Process | T1543 | Sandbox dynamic analysis (filesystem diff) |
| Stored Data Manipulation | T1565.001 | Sandbox dynamic analysis (file write detection) |

## Recommandations

### Pour les utilisateurs

1. Utiliser `muaddib install <pkg>` au lieu de `npm install` pour scanner avant installation
2. Mettre a jour les IOCs regulierement (`muaddib update`)
3. Utiliser le mode `--explain` pour comprendre les detections
4. Utiliser `--breakdown` pour comprendre la decomposition du score
5. Integrer dans CI/CD avec sortie SARIF
6. Configurer les pre-commit hooks (`muaddib init-hooks`) pour scanner a chaque commit
7. Utiliser `muaddib diff` en CI pour ne bloquer que les nouvelles menaces
8. Valider la couverture avec `muaddib replay` regulierement

### Pour les equipes securite

1. Completer avec une analyse dynamique (`muaddib sandbox <pkg>`)
2. Monitorer les nouveaux packages avant adoption
3. Utiliser `--sarif` pour integration GitHub Security
4. Utiliser `muaddib serve` pour integration SIEM via threat feed JSON
5. Suivre le taux de faux positifs avec `muaddib stats --daily`
6. Monitorer les lead times de detection avec `muaddib detections --stats`
7. Contribuer des IOCs via PR sur le repo
8. Utiliser le mode `--paranoid` pour les projets critiques

## Contacts

- Repository: https://github.com/DNSZLSK/muad-dib
- Issues: https://github.com/DNSZLSK/muad-dib/issues
