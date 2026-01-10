<p align="center">
  <img src="MUADDIBLOGO.png" alt="MUAD'DIB Logo" width="200">
</p>

<h1 align="center">MUAD'DIB</h1>

<p align="center">
  <strong>Detection et reponse aux menaces supply-chain npm</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/npm/v/muaddib-scanner" alt="npm version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/node-%3E%3D18-brightgreen" alt="Node">
  <img src="https://img.shields.io/badge/IOCs-930%2B-red" alt="IOCs">
</p>

<p align="center">
  <a href="#installation">Installation</a> |
  <a href="#utilisation">Utilisation</a> |
  <a href="#features">Features</a> |
  <a href="#vs-code">VS Code</a> |
  <a href="#discord">Discord</a>
</p>

---

## Pourquoi MUAD'DIB ?

Les attaques supply chain npm explosent. Shai-Hulud a compromis 25K+ repos en 2025. Les outils existants detectent, mais n'aident pas a repondre.

MUAD'DIB detecte ET guide votre reponse.

| Feature | MUAD'DIB | Socket | Snyk | Opengrep |
|---------|----------|--------|------|----------|
| Detection IOC | Oui | Oui | Oui | Non |
| Analyse AST | Oui | Oui | Oui | Oui |
| Analyse Dataflow | Oui | Non | Non | Oui |
| Detection Typosquatting | Oui | Oui | Oui | Non |
| Playbooks Reponse | Oui | Non | Non | Non |
| Score de Risque | Oui | Oui | Oui | Non |
| SARIF / GitHub Security | Oui | Oui | Oui | Oui |
| Mapping MITRE ATT&CK | Oui | Non | Non | Non |
| Webhooks Discord/Slack | Oui | Non | Non | Non |
| Extension VS Code | Oui | Oui | Oui | Non |
| Mode Paranoid | Oui | Non | Non | Non |
| Mode Daemon | Oui | Non | Non | Non |
| 100% Open Source | Oui | Non | Non | Oui |
| Docker Sandbox | Yes | No | No | No |

---

### Installation

Cherchez "MUAD'DIB" dans les Extensions VS Code, ou :
```bash
marketplace.visualstudio.com/items?itemName=dnszlsk.muaddib-vscode
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

Lance un menu interactif pour vous guider a travers toutes les fonctionnalites.

### Installation securisee
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

### Mode explain (details complets)
```bash
muaddib scan . --explain
```

Affiche pour chaque detection :
- Rule ID
- Technique MITRE ATT&CK
- References (articles, CVEs)
- Playbook de reponse

### Export
```bash
muaddib scan . --json > results.json     # JSON
muaddib scan . --html rapport.html       # HTML
muaddib scan . --sarif results.sarif     # SARIF (GitHub Security)
```

### Seuil de severite
```bash
muaddib scan . --fail-on critical  # Fail seulement sur CRITICAL
muaddib scan . --fail-on high      # Fail sur HIGH et CRITICAL (defaut)
muaddib scan . --fail-on medium    # Fail sur MEDIUM, HIGH, CRITICAL
```

### Mode paranoid
```bash
muaddib scan . --paranoid
```

Detection ultra-stricte avec moins de tolerance. Utile pour les projets critiques. Detecte tout acces reseau, execution de sous-processus, evaluation de code dynamique et acces aux fichiers sensibles.

### Webhook Discord/Slack
```bash
muaddib scan . --webhook "https://discord.com/api/webhooks/..."
```

Envoie une alerte avec le score et les menaces sur Discord ou Slack.

### Surveillance temps reel
```bash
muaddib watch .
```

### Mode daemon
```bash
muaddib daemon
muaddib daemon --webhook "https://discord.com/api/webhooks/..."
```

Surveille automatiquement tous les `npm install` et scanne les nouveaux packages.

### Mise a jour des IOCs
```bash
muaddib update
```

### Scraper de nouveaux IOCs
```bash
muaddib scrape
```

Recupere les derniers packages malveillants depuis plusieurs sources de threat intelligence :
- Shai-Hulud 2.0 Detector (GitHub)
- Datadog Security Labs
- OSV.dev
- Socket.dev reports
- Phylum Research
- AlienVault OTX
- Aikido Intel

---

### Sandbox Docker
```bash
muaddib sandbox <nom-package>
```

Analyse un package dans un container Docker isole. Capture :
- Connexions reseau (detecte exfiltration vers hosts suspects)
- Acces fichiers (detecte vol credentials : .npmrc, .ssh, .aws, .env)
- Spawn de processus (detecte reverse shells, abus curl/wget)

Necessite Docker Desktop installe.
```bash
muaddib sandbox lodash          # Package safe
muaddib sandbox suspicious-pkg  # Analyser un package inconnu
```

## Features

### Detection typosquatting

MUAD'DIB detecte les packages dont le nom ressemble a un package populaire :
```
[HIGH] Package "lodahs" ressemble a "lodash" (swapped_chars). Possible typosquatting.
```

### Analyse dataflow

Detecte quand du code lit des credentials ET les envoie sur le reseau :
```
[CRITICAL] Flux suspect: lecture credentials (readFileSync, GITHUB_TOKEN) + envoi reseau (fetch)
```

### Attaques detectees

| Campagne | Packages | Status |
|----------|----------|--------|
| Shai-Hulud v1 (Sept 2025) | @ctrl/tinycolor, ng2-file-upload | Detecte |
| Shai-Hulud v2 (Nov 2025) | @asyncapi/specs, posthog-node, kill-port | Detecte |
| Shai-Hulud v3 (Dec 2025) | @vietmoney/react-big-calendar | Detecte |
| event-stream (2018) | flatmap-stream, event-stream | Detecte |
| eslint-scope (2018) | eslint-scope | Detecte |
| Protestware | node-ipc, colors, faker | Detecte |
| Typosquats | crossenv, mongose, babelcli | Detecte |

### Techniques detectees

| Technique | MITRE | Detection |
|-----------|-------|-----------|
| Vol credentials (.npmrc, .ssh) | T1552.001 | AST |
| Exfiltration env vars | T1552.001 | AST |
| Execution code distant | T1105 | Pattern |
| Reverse shell | T1059.004 | Pattern |
| Dead man's switch | T1485 | Pattern |
| Code obfusque | T1027 | Heuristiques |
| Typosquatting | T1195.002 | Levenshtein |
| Supply chain compromise | T1195.002 | IOC matching |

---

## VS Code

L'extension VS Code scanne automatiquement vos projets npm.

### Installation

Cherchez "MUAD'DIB" dans les Extensions VS Code, ou :

```bash

```

### Commandes

- `MUAD'DIB: Scan Project` - Scanner tout le projet
- `MUAD'DIB: Scan Current File` - Scanner le fichier actuel

### Configuration

- `muaddib.autoScan` - Scanner automatiquement a l'ouverture (defaut: true)
- `muaddib.webhookUrl` - URL webhook Discord/Slack
- `muaddib.failLevel` - Niveau d'alerte (critical/high/medium/low)

---

## Integration CI/CD

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
+-- IOC Match (930+ packages, YAML/JSON DB)
+-- AST Parse (acorn)
+-- Pattern Matching (shell, scripts)
+-- Typosquat Detection (Levenshtein)
+-- Paranoid Mode (ultra-strict)
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

### Developper
```bash
git clone https://github.com/DNSZLSK/muad-dib
cd muad-dib
npm install
npm test
```

## Communaute

- Discord: https://discord.gg/y8zxSmue

---

## Documentation

- [Threat Model](docs/threat-model.md) - Ce que MUAD'DIB detecte et ne detecte pas
- [IOCs YAML](iocs/) - Base de donnees des menaces

---

## Licence

MIT

---

<p align="center">
  <strong>The spice must flow. The worms must die.</strong>
</p>
