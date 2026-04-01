<p align="center">
  <img src="assets/muaddibLogo.png" alt="MUAD'DIB Logo" width="700">
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/muaddib-scanner"><img src="https://img.shields.io/npm/v/muaddib-scanner" alt="npm version"></a>
  <a href="https://github.com/DNSZLSK/muad-dib/actions/workflows/scan.yml"><img src="https://github.com/DNSZLSK/muad-dib/actions/workflows/scan.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/DNSZLSK/muad-dib"><img src="https://codecov.io/gh/DNSZLSK/muad-dib/branch/master/graph/badge.svg" alt="Coverage"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/DNSZLSK/muad-dib"><img src="https://api.scorecard.dev/projects/github.com/DNSZLSK/muad-dib/badge" alt="OpenSSF Scorecard"></a>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/node-%3E%3D18-brightgreen" alt="Node">
  <img src="https://img.shields.io/badge/IOCs-225%2C000%2B-red" alt="IOCs">
</p>

<p align="center">
  <a href="#installation">Installation</a> |
  <a href="#utilisation">Utilisation</a> |
  <a href="#fonctionnalités">Fonctionnalités</a> |
  <a href="#vs-code">VS Code</a> |
  <a href="#ci-cd">CI/CD</a>
</p>

<p align="center">
  <a href="README.md">English version</a>
</p>

---

## Pourquoi MUAD'DIB ?

Les attaques supply-chain npm et PyPI explosent. Shai-Hulud a compromis 25K+ repos en 2025. Les outils existants détectent, mais n'aident pas à répondre.

MUAD'DIB combine **14 scanners paralleles** (200 regles de detection), un **moteur de desobfuscation**, une **analyse dataflow inter-module**, du **scoring compose**, des **classifiers ML** (XGBoost), et un sandbox gVisor/Docker pour detecter les menaces connues et les patterns comportementaux suspects dans les packages npm et PyPI.

---

## Positionnement

MUAD'DIB est un outil éducatif et une première ligne de défense gratuite. Il détecte les menaces npm et PyPI **connues** (225 000+ IOCs) et les patterns suspects basiques.

**Pour une protection enterprise**, utilisez :
- [Socket.dev](https://socket.dev) - Analyse comportementale ML, sandboxing cloud
- [Snyk](https://snyk.io) - Base de vulnérabilités massive, intégrations CI/CD
- [Opengrep](https://opengrep.dev) - Analyse dataflow avancée, règles Semgrep

MUAD'DIB ne remplace pas ces outils. Il les complète pour les devs qui veulent une vérification rapide et gratuite avant d'installer un package inconnu.

---

## Installation

### npm (recommandé)

```bash
npm install -g muaddib-scanner
```

### Depuis les sources

```bash
git clone https://github.com/DNSZLSK/muad-dib
cd muad-dib
npm install
npm link
```

---

## Utilisation

### Scan basique

```bash
muaddib scan .
muaddib scan /chemin/vers/projet
```

Scanne les dépendances npm (package.json, node_modules) et Python (requirements.txt, setup.py, pyproject.toml).

### Mode interactif

```bash
muaddib
```

Lance un menu interactif pour vous guider à travers toutes les fonctionnalités.

### Installation sécurisée

```bash
muaddib install <package>
muaddib install lodash axios --save-dev
muaddib i express -g
muaddib install suspicious-pkg --force    # Forcer l'installation malgré les menaces
```

Scanne les packages AVANT installation. Bloque les packages malveillants connus.

### Score de risque

Chaque scan affiche un score de risque 0-100 :

```
[SCORE] 58/100 [***********---------] HIGH
```

### Mode explain (détails complets)

```bash
muaddib scan . --explain
```

Affiche pour chaque détection :
- Rule ID
- Technique MITRE ATT&CK
- Références (articles, CVEs)
- Playbook de réponse

### Export

```bash
muaddib scan . --json > results.json     # JSON
muaddib scan . --html report.html        # HTML
muaddib scan . --sarif results.sarif     # SARIF (GitHub Security)
```

### Seuil de sévérité

```bash
muaddib scan . --fail-on critical  # Fail seulement sur CRITICAL
muaddib scan . --fail-on high      # Fail sur HIGH et CRITICAL (défaut)
muaddib scan . --fail-on medium    # Fail sur MEDIUM, HIGH, CRITICAL
```

### Mode paranoid

```bash
muaddib scan . --paranoid
```

Détection ultra-stricte avec moins de tolérance. Utile pour les projets critiques. Détecte tout accès réseau, exécution de sous-processus, évaluation de code dynamique et accès aux fichiers sensibles.

### Webhook Discord/Slack

```bash
muaddib scan . --webhook "https://discord.com/api/webhooks/..."
```

Envoie une alerte avec le score et les menaces sur Discord ou Slack. Filtrage strict (v2.1.2) : les alertes ne sont envoyées que pour les correspondances IOC, les menaces confirmées par sandbox, ou l'exfiltration de canary tokens — réduisant le bruit des détections heuristiques seules.

### Surveillance temps réel

```bash
muaddib watch .
```

### Mode daemon

```bash
muaddib daemon
muaddib daemon --webhook "https://discord.com/api/webhooks/..."
```

Surveille automatiquement tous les `npm install` et scanne les nouveaux packages.

### Mise à jour IOCs (rapide, ~5 secondes)

```bash
muaddib update
```

Charge les 225 000+ IOCs inclus dans le package, fusionne les IOCs YAML et les sources GitHub additionnelles (GenSecAI, DataDog). Lancez cette commande après `npm install` pour un rafraîchissement instantané des IOCs.

### Scrape IOCs (complet, ~5 minutes)

```bash
muaddib scrape
```

Rafraîchissement complet depuis toutes les sources primaires. Télécharge les dumps OSV pour npm et PyPI (~100-200 Mo), OSSF, et toutes les autres sources. Lancez cette commande quand vous voulez les données les plus récentes.

Sources :
- **OSV.dev npm dump** - Téléchargement en masse de toutes les entrées MAL-*
- **OSV.dev PyPI dump** - Téléchargement en masse de toutes les entrées PyPI MAL-*
- **GenSecAI Shai-Hulud 2.0 Detector** - Liste consolidée de 700+ packages Shai-Hulud
- **DataDog Security Labs** - IOCs consolidés de plusieurs vendors
- **OSSF Malicious Packages** - Base OpenSSF (8000+ rapports via OSV.dev)
- **GitHub Advisory Database** - Advisories tagués malware
- **Snyk Known Malware** - Packages malveillants historiques
- **IOCs Statiques** - Socket.dev, Phylum, packages supprimés de npm

### Sandbox Docker

```bash
muaddib sandbox <nom-package>
muaddib sandbox <nom-package> --strict
```

Analyse dynamique : installe le package dans un container Docker isolé et surveille le comportement à l'exécution via strace, tcpdump et diff filesystem.

Monitoring multi-couches :
- **Traçage système** (strace) : accès fichiers, spawn de processus, monitoring syscalls
- **Capture réseau** (tcpdump) : résolutions DNS avec IPs résolues, requêtes HTTP (méthode, host, path, body), détection TLS SNI
- **Diff filesystem** : snapshot avant/après install, détecte les fichiers créés dans des emplacements suspects
- **Détection exfiltration de données** : 16 patterns sensibles (tokens, credentials, clés SSH, clés privées, .env)
- **Environnement CI simulé** (v2.1.2) : simule un environnement CI (GITHUB_ACTIONS, GITLAB_CI, TRAVIS, CIRCLECI, JENKINS) pour déclencher les malwares CI-aware qui resteraient autrement dormants
- **Canary tokens enrichis** (v2.1.2) : 6 honeypots injectés comme variables d'environnement (GITHUB_TOKEN, NPM_TOKEN, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, SLACK_WEBHOOK_URL, DISCORD_WEBHOOK_URL). Si exfiltrés via réseau, DNS ou filesystem, déclenche une alerte CRITICAL avec score +50
- **Monkey-patching preload** (v2.4.9) : Instrumentation runtime via `NODE_OPTIONS=--require /opt/preload.js`. Patche les APIs de temps (Date.now, setTimeout→0, setInterval→immédiat), intercepte les appels réseau/fichiers/processus/env. Mode multi-run à [0h, 72h, 7j] pour détecter les malwares time-bomb (MITRE T1497.003)
- **Moteur de scoring** : score de risque 0-100 basé sur la sévérité des comportements

Utilisez `--strict` pour bloquer tout trafic réseau sortant non essentiel via iptables.

Nécessite Docker Desktop installé.

```bash
muaddib sandbox lodash          # Package safe
muaddib sandbox suspicious-pkg  # Analyser un package inconnu
```

### Rapport réseau sandbox

```bash
muaddib sandbox-report <nom-package>
muaddib sandbox-report <nom-package> --strict
```

Identique à `sandbox` mais affiche un rapport réseau détaillé : résolutions DNS, requêtes HTTP, connexions TLS, connexions bloquées (mode strict), et alertes d'exfiltration de données.

### Diff (comparer les versions)

```bash
muaddib diff <ref> [path]
```

Compare les menaces entre la version actuelle et un commit/tag précédent. Affiche uniquement les **NOUVELLES** menaces introduites depuis la référence.

```bash
muaddib diff HEAD~1             # Comparer avec le commit précédent
muaddib diff v1.2.0             # Comparer avec un tag
muaddib diff main               # Comparer avec une branche
muaddib diff abc1234            # Comparer avec un commit spécifique
```

Exemple de sortie :
```
[MUADDIB DIFF] Comparing abc1234 -> def5678

  Risk Score: 25 -> 45 (+20 worse)
  Threats:    3 -> 5

  NEW threats:     2
  REMOVED threats: 0
  Unchanged:       3

  NEW THREATS (introduced since v1.2.0)
  ------------------------------------
  1. [HIGH] suspicious_dependency
     Known malicious package detected
     File: package.json
```

Utilisez en CI pour ne bloquer que sur les **nouvelles** menaces, pas la dette technique existante :
```yaml
- run: muaddib diff ${{ github.event.pull_request.base.sha }} --fail-on high
```

### Hooks pre-commit

```bash
muaddib init-hooks [options]
```

Scanner automatiquement avant chaque commit. Supporte plusieurs systèmes de hooks :

```bash
muaddib init-hooks                        # Auto-detect (husky/pre-commit/git)
muaddib init-hooks --type husky           # Forcer husky
muaddib init-hooks --type pre-commit      # Forcer pre-commit framework
muaddib init-hooks --type git             # Forcer git hooks natifs
muaddib init-hooks --mode diff            # Ne bloquer que les NOUVELLES menaces
```

#### Avec pre-commit framework

Ajoutez à `.pre-commit-config.yaml` :
```yaml
repos:
  - repo: https://github.com/DNSZLSK/muad-dib
    rev: v2.10.43
    hooks:
      - id: muaddib-scan        # Scanner toutes les menaces
      # - id: muaddib-diff      # Ou: seulement les nouvelles
      # - id: muaddib-paranoid  # Ou: mode ultra-strict
```

#### Avec husky

```bash
npx husky add .husky/pre-commit "npx muaddib scan . --fail-on high"
# Ou pour le mode diff :
npx husky add .husky/pre-commit "npx muaddib diff HEAD --fail-on high"
```

#### Supprimer les hooks

```bash
muaddib remove-hooks [path]
```

Supprime tous les hooks MUAD'DIB (husky et git natif).

#### Git hooks natifs

```bash
muaddib init-hooks --type git
# Crée .git/hooks/pre-commit
```

### Moniteur Zero-Day

MUAD'DIB surveille en continu les registres npm et PyPI pour détecter les nouveaux packages en temps réel, en les scannant automatiquement avec analyse sandbox Docker et alertes webhook. Ce monitoring tourne en interne sur notre infrastructure — les menaces détectées alimentent la base IOC et l'API threat feed.

### Décomposition du score

```bash
muaddib scan . --breakdown
```

Affiche la décomposition explicable du score : contribution de chaque finding au score final, avec les poids par règle et multiplicateurs de sévérité.

### Replay ground truth

```bash
muaddib replay
muaddib ground-truth
```

Rejoue des attaques supply-chain réelles contre le scanner pour valider la couverture de détection. Résultat actuel : **46/49 détectées (93.9% TPR)** sur 51 samples (49 actifs).

4 misses hors scope : lottie-player, polyfill-io, trojanized-jquery (attaques browser-only DOM), websocket-rat (pattern risque FP).

### Version check

MUAD'DIB vérifie automatiquement les nouvelles versions au démarrage et vous notifie si une mise à jour est disponible.

---

## Fonctionnalités

### Support Python / PyPI

MUAD'DIB détecte et scanne automatiquement les projets Python :

- **requirements.txt** - Tous les formats incluant `-r` récursif, extras, marqueurs d'environnement
- **setup.py** - Extraction de `install_requires` et `setup_requires`
- **pyproject.toml** - Dépendances PEP 621 et dépendances Poetry

Les packages Python sont vérifiés contre 14 000+ packages PyPI malveillants connus (depuis OSV.dev) et testés pour le typosquatting contre les packages PyPI populaires (requests, numpy, flask, django, pandas, etc.) via la normalisation PEP 503.

```
[PYTHON] Detected Python project (3 dependency files)
  requirements.txt: 12 packages
  setup.py: 3 packages
  pyproject.toml: 8 packages

[CRITICAL] PyPI IOC match: malicious-pkg (all versions)
[HIGH] PyPI typosquat: "reqeusts" looks like "requests"
```

### Détection typosquatting

MUAD'DIB détecte les packages dont le nom ressemble à un package populaire (npm et PyPI) :

```
[HIGH] Package "lodahs" ressemble à "lodash" (swapped_chars). Possible typosquatting.
```

### Analyse dataflow

Détecte quand du code lit des credentials ET les envoie sur le réseau :

```
[CRITICAL] Flux suspect: lecture credentials (readFileSync, GITHUB_TOKEN) + envoi réseau (fetch)
```

### Scanner GitHub Actions

Détecte les patterns malveillants dans les fichiers YAML `.github/workflows/`, incluant les indicateurs de backdoor Shai-Hulud 2.0.

### Attaques détectées

| Campagne | Packages | Status |
|----------|----------|--------|
| GlassWorm (Mars 2026) | 433+ packages (Unicode invisible + Blockchain C2) | Détecté |
| Shai-Hulud v1 (Sept 2025) | @ctrl/tinycolor, ng2-file-upload | Détecté |
| Shai-Hulud v2 (Nov 2025) | @asyncapi/specs, posthog-node, kill-port | Détecté |
| Shai-Hulud v3 (Dec 2025) | @vietmoney/react-big-calendar | Détecté |
| event-stream (2018) | flatmap-stream, event-stream | Détecté |
| eslint-scope (2018) | eslint-scope | Détecté |
| Protestware | node-ipc, colors, faker | Détecté |
| Typosquats | crossenv, mongose, babelcli | Détecté |

### Techniques détectées

| Technique | MITRE | Détection |
|-----------|-------|-----------|
| Vol credentials (.npmrc, .ssh) | T1552.001 | AST |
| Exfiltration env vars | T1552.001 | AST |
| Exécution code distant | T1105 | Pattern |
| Reverse shell | T1059.004 | Pattern |
| Dead man's switch | T1485 | Pattern |
| Code obfusqué | T1027 | Heuristiques |
| Analyse entropie Shannon | T1027 | Calcul d'entropie |
| Typosquatting (npm + PyPI) | T1195.002 | Levenshtein |
| Supply chain compromise | T1195.002 | IOC matching |
| Package PyPI malveillant | T1195.002 | IOC matching |
| Sandbox analyse dynamique | Multiple | Docker + strace + tcpdump |
| Ajout soudain de script lifecycle | T1195.002 | Analyse temporelle |
| Injection d'API dangereuse entre versions | T1195.002 | Diff AST temporel |
| Anomalie de fréquence de publication | T1195.002 | Métadonnées registre |
| Changement de maintainer/publisher | T1195.002 | Métadonnées registre |
| Exfiltration de canary tokens | T1552.001 | Honey tokens sandbox |
| Weaponisation agent IA | T1059.004 | AST (flags s1ngularity/Nx) |
| Injection prompt config IA | T1059.004 | Scan fichiers (.cursorrules, CLAUDE.md) |
| Vol credentials CLI (gh, gcloud, aws) | T1552.001 | AST |
| Dropper binaire (chmod + exec /tmp) | T1105 | AST |
| Hooking prototype (fetch, XMLHttpRequest) | T1557 | AST |
| Injection workflow (.github/workflows) | T1195.002 | AST |
| Harvest crypto wallets | T1005 | Dataflow |
| Require cache poisoning | T1574.001 | AST |
| Staged eval decode (eval+atob/Buffer) | T1140 | AST |
| Désobfuscation (string concat, charcode, base64, hex) | T1140 | Pré-traitement AST |
| Dataflow cross-fichiers (exfiltration inter-module) | T1041 | Module graph |

---

## Détection d'anomalies supply chain (v2.0)

MUAD'DIB 2.0 introduit un changement de paradigme : de la **détection par IOC** (réactive, nécessite des menaces connues) à la **détection comportementale d'anomalies** (proactive, détecte les menaces inconnues en repérant les changements suspects).

Les scanners supply-chain traditionnels reposent sur des listes de packages malveillants connus. Le problème : ils ne détectent les menaces qu'APRÈS leur identification et signalement. Des attaques comme **ua-parser-js** (2021), **event-stream** (2018) et **Shai-Hulud** (2025) sont passées inaperçues pendant des heures ou des jours car aucun IOC n'existait encore.

MUAD'DIB 2.0 ajoute 5 features de détection comportementale capables d'attraper ces attaques **avant** leur apparition dans une base d'IOC, en analysant ce qui a changé entre les versions d'un package.

### Nouvelles features

#### 1. Détection soudaine de scripts lifecycle (`--temporal`)

Détecte quand des scripts `preinstall`, `install` ou `postinstall` apparaissent soudainement dans une nouvelle version d'un package qui n'en avait jamais. C'est le vecteur d'attaque #1 des attaques supply-chain.

```bash
muaddib scan . --temporal
```

#### 2. Diff AST temporel (`--temporal-ast`)

Télécharge les deux dernières versions de chaque dépendance et compare leur AST (Abstract Syntax Tree) pour détecter les APIs dangereuses nouvellement ajoutées : `child_process`, `eval`, `Function`, `net.connect`, `process.env`, `fetch`, etc.

```bash
muaddib scan . --temporal-ast
```

#### 3. Anomalie de fréquence de publication (`--temporal-publish`)

Détecte les patterns de publication anormaux : rafale de versions en 24h, package dormant soudainement mis à jour après 6+ mois, succession rapide de versions (plusieurs releases en moins d'1h).

```bash
muaddib scan . --temporal-publish
```

#### 4. Détection de changement de maintainer (`--temporal-maintainer`)

Détecte les changements de maintainers entre versions : nouveau maintainer ajouté, seul maintainer remplacé (pattern event-stream), noms de maintainers suspects, nouveau publisher.

```bash
muaddib scan . --temporal-maintainer
```

#### 5. Canary Tokens / Honey Tokens (sandbox)

Injecte de faux credentials dans l'environnement sandbox avant d'installer un package. Si le package tente d'exfiltrer ces honey tokens via HTTP, DNS, filesystem ou stdout, il est signalé comme malveillant confirmé.

6 honeypots sont injectés :
- `GITHUB_TOKEN` / `NPM_TOKEN` — Tokens de registre
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` — Credentials cloud
- `SLACK_WEBHOOK_URL` / `DISCORD_WEBHOOK_URL` — Webhooks de messagerie

Les tokens dynamiques (aléatoires par session, depuis `canary-tokens.js`) et les tokens statiques de fallback (dans `sandbox-runner.sh`) sont utilisés pour une défense en profondeur.

```bash
muaddib sandbox suspicious-package
```

### Scan temporel complet

Activer toutes les features d'analyse temporelle en une commande :

```bash
muaddib scan . --temporal-full
```

### Exemples d'utilisation

```bash
# Scan comportemental complet (5 features)
muaddib scan . --temporal-full

# Détection lifecycle scripts uniquement
muaddib scan . --temporal

# Diff AST + changement maintainer
muaddib scan . --temporal-ast --temporal-maintainer

# Sandbox avec canary tokens (activé par défaut)
muaddib sandbox suspicious-package

# Sandbox sans canary tokens
muaddib sandbox suspicious-package --no-canary
```

### Nouvelles règles de détection (v2.0)

| Rule ID | Nom | Sévérité | Feature |
|---------|-----|----------|---------|
| MUADDIB-TEMPORAL-001 | Ajout soudain de script lifecycle (Critique) | CRITICAL | `--temporal` |
| MUADDIB-TEMPORAL-002 | Ajout soudain de script lifecycle | HIGH | `--temporal` |
| MUADDIB-TEMPORAL-003 | Script lifecycle modifié | MEDIUM | `--temporal` |
| MUADDIB-TEMPORAL-AST-001 | API dangereuse ajoutée (Critique) | CRITICAL | `--temporal-ast` |
| MUADDIB-TEMPORAL-AST-002 | API dangereuse ajoutée (High) | HIGH | `--temporal-ast` |
| MUADDIB-TEMPORAL-AST-003 | API dangereuse ajoutée (Medium) | MEDIUM | `--temporal-ast` |
| MUADDIB-PUBLISH-001 | Rafale de publications détectée | HIGH | `--temporal-publish` |
| MUADDIB-PUBLISH-002 | Pic de package dormant | HIGH | `--temporal-publish` |
| MUADDIB-PUBLISH-003 | Succession rapide de versions | MEDIUM | `--temporal-publish` |
| MUADDIB-MAINTAINER-001 | Nouveau maintainer ajouté | HIGH | `--temporal-maintainer` |
| MUADDIB-MAINTAINER-002 | Maintainer suspect détecté | CRITICAL | `--temporal-maintainer` |
| MUADDIB-MAINTAINER-003 | Seul maintainer changé | HIGH | `--temporal-maintainer` |
| MUADDIB-MAINTAINER-004 | Nouveau publisher détecté | MEDIUM | `--temporal-maintainer` |
| MUADDIB-CANARY-001 | Exfiltration de canary token | CRITICAL | sandbox |

### Pourquoi c'est important

Ces features détectent des attaques comme :
- **Shai-Hulud** (2025) : Détecté par temporal lifecycle + AST diff (ajout soudain de `postinstall` + `child_process`)
- **ua-parser-js** (2021) : Détecté par changement maintainer + détection lifecycle
- **event-stream** (2018) : Détecté par changement de seul maintainer + AST diff (nouvelle dépendance `flatmap-stream` avec `eval`)
- **coa/rc** (2021) : Détecté par rafale de publications + détection lifecycle

Le tout sans avoir besoin d'un seul IOC.

---

## Sources IOC

MUAD'DIB agrège la threat intelligence de sources vérifiées uniquement :

| Source | Type | Couverture |
|--------|------|------------|
| [OSV.dev npm dump](https://osv.dev) | Bulk zip | 200 000+ entrées npm MAL-* |
| [OSV.dev PyPI dump](https://osv.dev) | Bulk zip | 14 000+ entrées PyPI MAL-* |
| [GenSecAI Shai-Hulud Detector](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector) | GitHub | 700+ packages Shai-Hulud |
| [DataDog Security Labs](https://github.com/DataDog/indicators-of-compromise) | GitHub | IOCs consolidés de 7 vendors |
| [OSSF Malicious Packages](https://github.com/ossf/malicious-packages) | API OSV | 8000+ rapports malware |
| [GitHub Advisory](https://github.com/advisories?query=type%3Amalware) | API OSV | Advisories tagués malware |
| Snyk Known Malware | Statique | Attaques historiques |
| Socket.dev / Phylum | Statique | Ajouts manuels |

---

## VS Code

L'extension VS Code scanne automatiquement vos projets npm.

### Installation

Cherchez "MUAD'DIB" dans les Extensions VS Code, ou :

```bash
code --install-extension dnszlsk.muaddib-vscode
```

### Commandes

- `MUAD'DIB: Scan Project` - Scanner tout le projet
- `MUAD'DIB: Scan Current File` - Scanner le fichier actuel

### Configuration

- `muaddib.autoScan` - Scanner automatiquement à l'ouverture (défaut: true)
- `muaddib.webhookUrl` - URL webhook Discord/Slack
- `muaddib.failLevel` - Niveau d'alerte (critical/high/medium/low)

---

## CI/CD

### GitHub Actions (Marketplace)

Utilisez l'action officielle MUAD'DIB depuis le GitHub Marketplace :

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: DNSZLSK/muad-dib@v1
        with:
          path: '.'
          fail-on: 'high'
          sarif: 'results.sarif'
```

#### Inputs de l'action

| Input | Description | Défaut |
|-------|-------------|--------|
| `path` | Chemin à scanner | `.` |
| `fail-on` | Sévérité minimum pour échec (critical/high/medium/low) | `high` |
| `sarif` | Chemin du fichier SARIF | `` |
| `paranoid` | Activer détection ultra-stricte | `false` |

#### Outputs de l'action

| Output | Description |
|--------|-------------|
| `sarif-file` | Chemin du fichier SARIF généré |
| `risk-score` | Score de risque (0-100) |
| `threats-count` | Nombre de menaces détectées |
| `exit-code` | Code de sortie (0 = clean) |

Les alertes apparaissent dans Security > Code scanning alerts.

---

## Architecture

```
MUAD'DIB 2.10.5 Scanner
|
+-- IOC Match (225 000+ packages, JSON DB)
|   +-- OSV.dev npm dump (200K+ entrées MAL-*)
|   +-- OSV.dev PyPI dump (14K+ entrées MAL-*)
|   +-- GenSecAI Shai-Hulud Detector
|   +-- DataDog Consolidated IOCs
|   +-- OSSF Malicious Packages (via OSV)
|   +-- GitHub Advisory (malware)
|   +-- Snyk Known Malware
|   +-- Static IOCs (Socket, Phylum)
|
+-- Pré-traitement Désobfuscation (v2.2.5, --no-deobfuscate pour désactiver)
|   +-- String concat folding, reconstruction CharCode
|   +-- Décodage Base64, résolution Hex array
|   +-- Propagation de constantes (Phase 2)
|
+-- Dataflow Inter-module (v2.2.6, --no-module-graph pour désactiver)
|   +-- Graphe de dépendances, annotation exports teintés
|   +-- Chaînes re-export 3 hops, analyse méthodes de classe
|   +-- Détection credential read → network sink cross-fichiers
|
+-- Graphe d'Intention (Intent Graph)
|   +-- Analyse cross-scanner des intentions malveillantes
|   +-- Corrélation entre signaux faibles de multiples scanners
|   +-- Élévation de sévérité sur combinaisons suspectes
|
+-- 14 Scanners Parallèles (200 règles)
|   +-- AST Parse (acorn) — eval/Function, credential CLI theft, binary droppers, prototype hooks
|   +-- Pattern Matching (shell, scripts)
|   +-- Typosquat Detection (npm + PyPI, Levenshtein)
|   +-- Python Scanner (requirements.txt, setup.py, pyproject.toml)
|   +-- Analyse Entropie Shannon
|   +-- GitHub Actions Scanner
|   +-- AI Config Scanner (.cursorrules, CLAUDE.md, copilot-instructions.md)
|   +-- Package, Dependencies, Hash, npm-registry, Dataflow scanners
|
+-- Détection d'Anomalies Supply Chain (v2.0)
|   +-- Détection Lifecycle Script Temporelle (--temporal)
|   +-- Diff AST Temporel (--temporal-ast)
|   +-- Anomalie Fréquence de Publication (--temporal-publish)
|   +-- Détection Changement Maintainer (--temporal-maintainer)
|   +-- Canary Tokens / Honey Tokens (sandbox)
|
+-- Validation & Observabilité (v2.1)
|   +-- Ground Truth Dataset (51 attaques réelles, 93.9% TPR)
|   +-- Logging Temps de Détection (first_seen, métriques lead time)
|   +-- Suivi Taux FP (stats quotidiennes, taux faux positifs)
|   +-- Décomposition Score (scoring explicable par règle)
|   +-- API Threat Feed (serveur HTTP, flux JSON pour SIEM)
|
+-- Réduction FP Post-traitement (v2.2.8-v2.3.1, v2.5.7-v2.5.8, v2.5.15-v2.5.16)
|   +-- Downgrade sévérité par comptage (dynamic_require, dataflow, module_compile, etc.)
|   +-- Cap scoring prototype_hook MEDIUM + whitelist HTTP client
|   +-- Obfuscation dans dist/build/.cjs/.mjs → LOW
|   +-- Filtrage env vars safe + préfixes
|   +-- Catégorisation source télémétrie dataflow (os.platform/arch → telemetry_read)
|   +-- Whitelist DEP (es5-ext, bootstrap-sass) + skip alias npm
|   +-- Audit IOC wildcards (v2.5.8) : FPR 10.8% → 6.0%
|   +-- P5 precision heuristique (v2.5.15) : 7 corrections
|   +-- P6 precision composes (v2.5.16) : 6 corrections
|
+-- Scoring Per-File Max (v2.2.11)
|   +-- Score = max(scores_par_fichier) + score_package_level
|   +-- Élimine l'accumulation de score sur de nombreux fichiers
|   +-- Menaces package-level (lifecycle, typosquat, IOC) scorées séparément
|
+-- Sandbox Monkey-Patching Preload (v2.4.9)
|   +-- Manipulation temps runtime (Date.now, setTimeout→0, setInterval→immédiat)
|   +-- Interception réseau/fichiers/processus/env et logging
|   +-- Multi-run [0h, 72h, 7j] pour détection time-bomb (T1497.003)
|
+-- Audit Sécurité (v2.5.0-v2.5.6)
|   +-- 41 issues remédiées (14 CRITICAL, 18 HIGH, 9 MEDIUM)
|
+-- ML Classifier (v2.10.0-v2.10.5)
|   +-- ML1 XGBoost malware detector (P=0.978, R=0.933, F1=0.955, 114 arbres)
|   +-- ML2 Bundler detector (P=0.992, R=1.000, F1=0.996, 98 arbres)
|   +-- Filtre T1 zone (score 20-34) avant sandbox
|
+-- Webhook Triage P1/P2/P3 (v2.10.5)
|   +-- P1 rouge : IOC, HC types, sandbox, canary tokens
|   +-- P2 orange : score >= 50, compounds, lifecycle+intent
|   +-- P3 jaune : reste (score 20-49 sans signal fort)
|
+-- Paranoid Mode (ultra-strict)
+-- Docker Sandbox (analyse comportementale, capture réseau, canary tokens, CI-aware, preload)
+-- Moniteur Zero-Day (interne : polling RSS npm + PyPI, alertes Discord, rapport quotidien)
|
v
Dataflow Analysis (credential read -> network send)
|
v
Threat Enrichment (rules, MITRE ATT&CK, playbooks)
|
v
Output (CLI, JSON, HTML, SARIF, Webhook, Threat Feed)
```

---

## Metriques d'evaluation

| Metrique | Resultat | Details |
|----------|----------|---------|
| **Wild TPR** (Datadog 17K) | **92.8%** (13 538/14 587 in-scope) | 17 922 packages. 3 335 sans JS (hors scope). Par categorie : compromised_lib 97.8%, malicious_intent 92.1% |
| **TPR** (Ground Truth) | **93.9%** (46/49) | 51 attaques reelles (49 actives). 3 hors scope : browser-only (3) |
| **FPR** (Benign curated) | **10.6%** (56/529) | 529 packages npm, vrai code source via `npm pack`, seuil > 20 |
| **FPR** (Benign random) | **7.5%** (15/200) | 200 packages npm aleatoires, echantillonnage stratifie |
| **ADR** (Adversarial + Holdout) | **94.0%** (101/107) | 67 adversariaux + 40 holdouts (107 disponibles), seuil global=20 |

**Benchmark Datadog 17K (v2.10.21)** — [DataDog Malicious Software Packages Dataset](https://github.com/DataDog/malicious-software-packages-dataset), 17 922 packages malveillants npm. Wild TPR : **92.8%** (13 538/14 587 in-scope). 3 335 packages sans fichiers JS exclus comme hors scope. Erreurs : 0.

| Metrique | Valeur |
|----------|--------|
| Total packages | 17 922 |
| Hors scope (pas de JS) | 3 335 |
| In-scope | 14 587 |
| Detectes | 13 538 |
| Misses (score=0, in-scope) | 1 049 |

**Par categorie :**
- compromised_lib : **97.8%** (904/924)
- malicious_intent : **92.1%** (12 582/13 663 in-scope, 3 335 hors scope)

Voir [Evaluation Methodology](docs/EVALUATION_METHODOLOGY.md#14-datadog-17k-benchmark).

**FPR par taille de package** — Le FPR correle lineairement avec la taille du package. Le scoring per-file max (v2.2.11) reduit significativement les FP sur les packages moyens/gros :

| Categorie | Packages | FP | FPR |
|-----------|----------|-----|-----|
| Petits (<10 fichiers JS) | 290 | 18 | **6.2%** |
| Moyens (10-50 fichiers JS) | 135 | 16 | 11.9% |
| Gros (50-100 fichiers JS) | 40 | 10 | 25.0% |
| Tres gros (100+ fichiers JS) | 62 | 25 | 40.3% |

**Progression FPR** : 0% (invalide, dirs vides, v2.2.0-v2.2.6) → 38% (premiere vraie mesure, v2.2.7) → 19.4% (v2.2.8) → 17.5% (v2.2.9) → ~13% (v2.2.11, scoring per-file max) → 8.9% (v2.3.0, P2) → 7.4% (v2.3.1, P3) → 6.0% (v2.5.8, P4 + audit IOC wildcards) → ~13.6% (v2.5.14, hardening audit) → **12.3%** (v2.5.16, P5+P6, 65/532) → **12.3%** (v2.6.1, module-graph bounded path — zero FP) → **12.1%** (v2.6.2, P7) → **12.9%** (v2.9.4, compound scoring + nouveaux detecteurs) → **10.8%** (v2.10.1, audit v3 FP reduction, 57/529) → **11.0%** (v2.10.5, ML + compounds, 58/529) → **10.6%** (v2.10.21, dataflow graduation + SDK heuristic, 56/529)

> **Note sur l'evolution du FPR :** Le FPR historique de 6.0% (v2.5.8) reposait sur un `BENIGN_PACKAGE_WHITELIST` qui excluait certains packages connus du scoring — un biais de data leakage supprime en v2.5.10. Le FPR actuel de 10.6% est une mesure honnete sans whitelisting, contre 529 packages benins reels. La baisse v2.10.5→v2.10.21 (-2 FP) vient de la graduation dataflow et de l'heuristique SDK.

**Progression holdout** (scores pre-tuning, regles gelees) :

| Holdout | Score | Focus |
|---------|-------|-------|
| v1 | 30% (3/10) | Patterns generaux |
| v2 | 40% (4/10) | Env charcode, lifecycle, prototype |
| v3 | 60% (6/10) | Require cache, DNS TXT, reverse shell |
| v4 | **80%** (8/10) | Efficacite desobfuscation |
| v5 | 50% (5/10) | Dataflow inter-module (nouveau scanner) |

- **Wild TPR** (Benchmark Datadog) : taux de detection sur 17 922 packages malveillants reels du [DataDog Malicious Software Packages Dataset](https://github.com/DataDog/malicious-software-packages-dataset). Wild TPR **92.8%** (13 538/14 587 in-scope). 3 335 packages sans fichiers JS exclus comme hors scope. Par categorie : compromised_lib 97.8%, malicious_intent 92.1%. Voir [Evaluation Methodology](docs/EVALUATION_METHODOLOGY.md#14-datadog-17k-benchmark).
- **TPR** (True Positive Rate) : taux de detection sur 49 attaques supply-chain reelles (event-stream, ua-parser-js, coa, flatmap-stream, eslint-scope, solana-web3js, et 43 autres). 4 misses : browser-only (lottie-player, polyfill-io, trojanized-jquery) ou risque FP (websocket-rat) — voir [Threat Model](docs/threat-model.md).
- **FPR** (False Positive Rate) : packages avec score > 20 sur 532 packages npm reels (code source scanne, pas des dirs vides). Le 6.2% sur les packages standard (<10 fichiers JS, 290 packages) est la metrique la plus representative pour un usage typique — la plupart des packages npm sont petits.
- **ADR** (Adversarial Detection Rate) : taux de detection sur 107 samples malveillants evasifs — 67 adversariaux (7 vagues red team) + 40 holdouts (4 batches de 10). 107 disponibles sur disque, seuil global=20.
- **Holdout** (pre-tuning) : taux de detection sur 10 samples jamais vus avec regles gelees (mesure de generalisation)

Datasets : 14 587 samples Datadog in-scope, 529 npm curated + 200 npm random + 132 PyPI packages benins, 107 samples adversariaux/holdout, 51 attaques ground-truth (65 packages malveillants documentes). **3034 tests**, 65 fichiers.

Voir [Evaluation Methodology](docs/EVALUATION_METHODOLOGY.md) pour le protocole experimental complet.

---

## Contribuer

### Ajouter des IOCs

Editez les fichiers YAML dans `iocs/` :

```yaml
- id: NEW-MALWARE-001
  name: "malicious-package"
  version: "*"
  severity: critical
  confidence: high
  source: community
  description: "Description de la menace"
  references:
    - https://example.com/article
  mitre: T1195.002
```

### Développer

```bash
git clone https://github.com/DNSZLSK/muad-dib
cd muad-dib
npm install
npm test
```

### Tests

- **3034 tests unitaires/integration** sur 65 fichiers modulaires via [Codecov](https://codecov.io/gh/DNSZLSK/muad-dib)
- **56 tests de fuzzing** - YAML malforme, JSON invalide, fichiers binaires, ReDoS, unicode, inputs 10MB
- **Benchmark Datadog 17K** - 14 587 packages malveillants in-scope, 92.8% Wild TPR (13 538/14 587 in-scope, 3 335 hors scope sans JS). compromised_lib 97.8%, malicious_intent 92.1%
- **107 samples adversariaux/holdout** - 67 adversariaux + 40 holdouts, 101/107 taux de detection sur samples disponibles (94.0% ADR, seuil global=20)
- **Validation ground truth** - 51 attaques reelles (46/49 detectees = 93.9% TPR). 3 hors scope : browser-only (lottie-player, polyfill-io, trojanized-jquery)
- **Validation faux positifs** - 10.6% FPR curated (56/529), 7.5% FPR random (15/200) sur vrai code source npm via `npm pack`
- **Audit ESLint securite** - `eslint-plugin-security` avec 14 regles activees

---

## Communaute

- Discord : https://discord.gg/y8zxSmue

---

## Documentation

- [Blog](https://dnszlsk.github.io/muad-dib/blog/) - Articles techniques sur la detection de menaces supply-chain
- [Carnet de bord](CARNET_DE_BORD_MUADDIB.md) - Journal de developpement du projet
- [Evaluation Methodology](EVALUATION_METHODOLOGY.md) - Protocole experimental, scores holdout bruts, sources d'attaques
- [Threat Model](threat-model.md) - Ce que MUAD'DIB detecte et ne detecte pas
- [Rapport d'audit securite v1.4.1](MUADDIB_Security_Audit_Report_v1.4.1.pdf) - Audit complet (58 issues corrigees)
- [IOCs YAML](../iocs/) - Base de donnees des menaces

---

## Licence

MIT

---

<p align="center">
  <strong>The spice must flow. The worms must die.</strong>
</p>
