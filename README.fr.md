<p align="center">
  <img src="MUADDIBLOGO.png" alt="MUAD'DIB Logo" width="200">
</p>

<h1 align="center">MUAD'DIB</h1>

<p align="center">
  <strong>Détection et réponse aux menaces supply-chain npm</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/npm/v/muaddib-scanner" alt="npm version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/node-%3E%3D18-brightgreen" alt="Node">
  <img src="https://img.shields.io/badge/IOCs-1500%2B-red" alt="IOCs">
</p>

<p align="center">
  <a href="#installation">Installation</a> |
  <a href="#utilisation">Utilisation</a> |
  <a href="#features">Features</a> |
  <a href="#vs-code">VS Code</a> |
  <a href="#ci-cd">CI/CD</a>
</p>

<p align="center">
  <a href="README.md">English version</a>
</p>

---

## Pourquoi MUAD'DIB ?

Les attaques supply-chain npm explosent. Shai-Hulud a compromis 25K+ repos en 2025. Les outils existants détectent, mais n'aident pas à répondre.

MUAD'DIB détecte ET guide votre réponse.

---

## Positionnement

MUAD'DIB est un outil éducatif et une première ligne de défense gratuite. Il détecte les menaces npm **connues** (1500+ IOCs) et les patterns suspects basiques.

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
muaddib scan . --html rapport.html       # HTML
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

### Mise à jour des IOCs

```bash
muaddib update
```

### Scraper de nouveaux IOCs

```bash
muaddib scrape
```

Récupère les derniers packages malveillants depuis des sources de threat intelligence vérifiées :
- **GenSecAI Shai-Hulud 2.0 Detector** - Liste consolidée de 700+ packages Shai-Hulud
- **DataDog Security Labs** - IOCs consolidés de plusieurs vendors
- **OSSF Malicious Packages** - Base OpenSSF (8000+ rapports via OSV.dev)
- **GitHub Advisory Database** - Advisories tagués malware
- **Snyk Known Malware** - Packages malveillants historiques
- **IOCs Statiques** - Socket.dev, Phylum, packages supprimés de npm

### Sandbox Docker

```bash
muaddib sandbox <nom-package>
```

Analyse un package dans un container Docker isolé. Capture :
- Connexions réseau (détecte exfiltration vers hosts suspects)
- Accès fichiers (détecte vol credentials : .npmrc, .ssh, .aws, .env)
- Spawn de processus (détecte reverse shells, abus curl/wget)

Nécessite Docker Desktop installé.

```bash
muaddib sandbox lodash          # Package safe
muaddib sandbox suspicious-pkg  # Analyser un package inconnu
```

---

## Features

### Détection typosquatting

MUAD'DIB détecte les packages dont le nom ressemble à un package populaire :

```
[HIGH] Package "lodahs" ressemble à "lodash" (swapped_chars). Possible typosquatting.
```

### Analyse dataflow

Détecte quand du code lit des credentials ET les envoie sur le réseau :

```
[CRITICAL] Flux suspect: lecture credentials (readFileSync, GITHUB_TOKEN) + envoi réseau (fetch)
```

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
| Typosquatting | T1195.002 | Levenshtein |
| Supply chain compromise | T1195.002 | IOC matching |

---

## Sources IOC

MUAD'DIB agrège la threat intelligence de sources vérifiées uniquement :

| Source | Type | Couverture |
|--------|------|------------|
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

### GitHub Actions

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
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install -g muaddib-scanner
      - run: muaddib scan . --sarif results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

Les alertes apparaissent dans Security > Code scanning alerts.

---

## Architecture

```
MUAD'DIB Scanner
|
+-- IOC Match (1500+ packages, JSON DB)
|   +-- GenSecAI Shai-Hulud Detector
|   +-- DataDog Consolidated IOCs
|   +-- OSSF Malicious Packages (via OSV)
|   +-- GitHub Advisory (malware)
|   +-- Snyk Known Malware
|   +-- Static IOCs (Socket, Phylum)
|
+-- AST Parse (acorn)
+-- Pattern Matching (shell, scripts)
+-- Typosquat Detection (Levenshtein)
+-- Paranoid Mode (ultra-strict)
+-- Docker Sandbox (behavioral analysis)
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

---

## Communauté

- Discord: https://discord.gg/y8zxSmue

---

## Documentation

- [Threat Model](docs/threat-model.md) - Ce que MUAD'DIB détecte et ne détecte pas
- [IOCs YAML](iocs/) - Base de données des menaces

---

## Licence

MIT

---

<p align="center">
  <strong>The spice must flow. The worms must die.</strong>
</p>
