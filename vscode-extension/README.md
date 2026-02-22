# MUAD'DIB VS Code Extension

Supply-chain threat detection for npm and PyPI projects, directly in VS Code.

## Features

- **Scan Project** -- Analyse toutes les dependances npm/PyPI du workspace ouvert
- **Scan Current File** -- Analyse le fichier actif uniquement (.js, .json, .py, .toml, .yaml, .md)
- **Update IOCs** -- Telecharge les derniers indicateurs de compromission
- **Auto-scan** -- Scan automatique a l'ouverture du projet et a chaque modification de `package.json` ou `requirements.txt`
- **Diagnostics inline** -- Les menaces detectees apparaissent dans l'onglet "Problems" de VS Code
- **Rapport detaille** -- Panneau avec tableau colore par severite et liens cliquables vers les fichiers
- **Webhook alerts** -- Envoi optionnel des alertes vers Discord ou Slack
- **Scan annulable** -- Possibilite d'annuler un scan en cours depuis la notification
- **14 scanners specialises** -- AST, dataflow, obfuscation, typosquatting, IOC, AI config, etc.
- **94 regles de detection** -- Mappees sur le framework MITRE ATT&CK

## Prerequis

Le CLI `muaddib-scanner` doit etre installe globalement :

```bash
npm install -g muaddib-scanner
```

Requiert Node.js >= 18.0.0.

## Installation

### Depuis le Marketplace

1. Ouvrir VS Code
2. Extensions (Ctrl+Shift+X)
3. Chercher "MUAD'DIB Security Scanner"
4. Installer

Ou directement : [MUAD'DIB Security Scanner](https://marketplace.visualstudio.com/items?itemName=dnszlsk.muaddib-vscode)

### Depuis un VSIX

1. Build l'extension :
   ```bash
   cd vscode-extension
   npx @vscode/vsce package
   ```
2. Dans VS Code : Extensions > `...` > Install from VSIX > selectionner le `.vsix`

## Commandes

Raccourci : ouvrir la palette de commandes (Ctrl+Shift+P) et taper "MUAD'DIB".

| Commande | Description |
|----------|-------------|
| `MUAD'DIB: Scan Project` | Lance un scan complet du workspace |
| `MUAD'DIB: Scan Current File` | Scanne le fichier actuellement ouvert |
| `MUAD'DIB: Update IOCs` | Met a jour les indicateurs de compromission |

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `muaddib.autoScan` | boolean | `true` | Scanner automatiquement a l'ouverture du projet |
| `muaddib.webhookUrl` | string | `""` | URL du webhook Discord/Slack pour les alertes (HTTPS uniquement) |
| `muaddib.failLevel` | string | `"high"` | Niveau minimum de severite (`critical`, `high`, `medium`, `low`) |
| `muaddib.explain` | boolean | `false` | Afficher les explications detaillees pour chaque menace |
| `muaddib.paranoid` | boolean | `false` | Mode ultra-strict (plus de detections, plus de faux positifs) |
| `muaddib.temporalAnalysis` | boolean | `false` | Analyses temporelles (requetes reseau vers npm/PyPI) |

## Fonctionnement

L'extension s'active automatiquement lorsqu'un `package.json`, `requirements.txt`, `pyproject.toml` ou `setup.py` est detecte dans le workspace.

Elle execute `muaddib-scanner scan --json` sur le workspace ou le fichier courant, puis convertit les resultats en diagnostics VS Code (warnings/errors dans l'onglet Problems).

Le scan detecte :
- Packages npm/PyPI malveillants connus (225 000+ IOCs)
- Patterns d'attaque supply-chain (lifecycle scripts, obfuscation, exfiltration)
- Typosquatting sur les noms de packages
- Flux de donnees inter-modules (credentials -> exfiltration)
- Injection dans les fichiers de configuration AI (.cursorrules, CLAUDE.md, etc.)

## Niveaux de severite

| Niveau | VS Code | Signification |
|--------|---------|---------------|
| CRITICAL | Error (rouge) | Package quasi certainement malveillant |
| HIGH | Error (rouge) | Indicateurs forts d'intention malveillante |
| MEDIUM | Warning (jaune) | Patterns suspects a investiguer |
| LOW | Information (bleu) | Preoccupations mineures ou informationnelles |

## Screenshots

<!-- TODO: Add screenshots -->
*Screenshots a venir*

## Licence

MIT - Voir [LICENSE](LICENSE) pour les details.

## Liens

- [MUAD'DIB CLI](https://github.com/DNSZLSK/muad-dib)
- [Signaler un bug](https://github.com/DNSZLSK/muad-dib/issues)
