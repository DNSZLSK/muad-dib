<p align="center">
  <img src="assets/logo2removebg.png" alt="MUAD'DIB Logo" width="700">
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

MUAD'DIB combine analyse statique + analyse dynamique (sandbox Docker) + **détection comportementale d'anomalies** (v2.0) pour détecter les menaces ET guider votre réponse — même avant leur apparition dans une base d'IOC.

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

Envoie une alerte avec le score et les menaces sur Discord ou Slack.

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
    rev: v1.8.0
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

MUAD'DIB intègre un moniteur zero-day capable de scanner chaque nouveau package npm et PyPI en temps réel avec analyse sandbox Docker et alertes webhook.

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

Injecte de faux credentials (GITHUB_TOKEN, NPM_TOKEN, clés AWS) dans l'environnement sandbox avant d'installer un package. Si le package tente d'exfiltrer ces honey tokens via HTTP, DNS ou stdout, il est signalé comme malveillant confirmé.

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
MUAD'DIB 2.0 Scanner
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
+-- 12 Scanners Parallèles
|   +-- AST Parse (acorn)
|   +-- Pattern Matching (shell, scripts)
|   +-- Typosquat Detection (npm + PyPI, Levenshtein)
|   +-- Python Scanner (requirements.txt, setup.py, pyproject.toml)
|   +-- Analyse Entropie Shannon
|   +-- GitHub Actions Scanner
|   +-- Package, Dependencies, Hash, npm-registry, Dataflow scanners
|
+-- Détection d'Anomalies Supply Chain (v2.0)
|   +-- Détection Lifecycle Script Temporelle (--temporal)
|   +-- Diff AST Temporel (--temporal-ast)
|   +-- Anomalie Fréquence de Publication (--temporal-publish)
|   +-- Détection Changement Maintainer (--temporal-maintainer)
|   +-- Canary Tokens / Honey Tokens (sandbox)
|
+-- Paranoid Mode (ultra-strict)
+-- Docker Sandbox (analyse comportementale, capture réseau, canary tokens)
+-- Moniteur Zero-Day (polling RSS npm + PyPI, alertes Discord, rapport quotidien)
|
v
Dataflow Analysis (credential read -> network send)
|
v
Threat Enrichment (rules, MITRE ATT&CK, playbooks)
|
v
Output (CLI, JSON, HTML, SARIF, Webhook)
```

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

- **541 tests unitaires/intégration** - 80% coverage via [Codecov](https://codecov.io/gh/DNSZLSK/muad-dib)
- **56 tests de fuzzing** - YAML malformé, JSON invalide, fichiers binaires, ReDoS, unicode, inputs 10MB
- **15 tests adversariaux** - Packages malveillants simulés, taux de détection 15/15
- **8 tests multi-facteur typosquat** - Cas limites et comportement cache
- **Audit ESLint sécurité** - `eslint-plugin-security` avec 14 règles activées

---

## Communauté

- Discord: https://discord.gg/y8zxSmue

---

## Documentation

- [Threat Model](docs/threat-model.md) - Ce que MUAD'DIB détecte et ne détecte pas
- [Rapport d'audit sécurité v1.4.1](docs/MUADDIB_Security_Audit_Report_v1.4.1.pdf) - Audit complet (58 issues corrigées)
- [IOCs YAML](iocs/) - Base de données des menaces

---

## Licence

MIT

---

<p align="center">
  <strong>The spice must flow. The worms must die.</strong>
</p>
