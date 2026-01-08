# Carnet de Bord - Projet MUAD'DIB

---

## Genese du Projet

### Le Contexte (1er janvier 2026)

En novembre 2025, un ver auto-replicatif appele **Shai-Hulud 2.0** a compromis **796 packages npm** totalisant plus de **20 millions de telechargements hebdomadaires**. Des projets majeurs comme Zapier, PostHog, Postman ont ete temporairement compromis, affectant plus de 25 000 depots GitHub.

Le ver vole des credentials (GitHub tokens, npm tokens, cles AWS/Azure/GCP) et les exfiltre via des repos GitHub publics marques "Sha1-Hulud: The Second Coming".

**L'idee** : Creer un outil open source, gratuit, pour detecter ces attaques supply-chain AVANT qu'elles ne compromettent un projet.

### Pourquoi "MUAD'DIB" ?

Reference a Dune de Frank Herbert. Dans le roman, Muad'Dib est le nom Fremen de Paul Atreides, celui qui combat et dompte les vers geants (Shai-Hulud). Le projet combat le ver npm du meme nom.

---

## Chronologie Detaillee

### Jour 1 - 1er janvier 2026 : La Fondation

**Session de 12h+ de developpement intensif**

#### Decisions Architecturales Cles

J'ai commence avec un plan ambitieux incluant de l'IA (scikit-learn, TensorFlow) pour la detection d'anomalies. Claude m'a recadre :

> "Oublie l'IA pour la v1. Concentre-toi sur l'analyse AST des comportements et l'integration des IOCs existants. C'est moins sexy mais c'est ce qui protege reellement."

**Architecture retenue** :
```
MUAD'DIB/
├── bin/muaddib.js        # CLI principal
├── src/
│   ├── scanner/          # Detection
│   │   ├── ast.js        # Analyse AST (acorn)
│   │   ├── dependencies.js
│   │   ├── obfuscation.js
│   │   └── shell.js
│   ├── ioc/              # Indicateurs de Compromission
│   │   ├── updater.js
│   │   └── feeds.js
│   └── response/         # Reponse incident
│       └── playbooks.js
└── data/iocs.json        # Base IOCs locale
```

#### Implementation Core

**1. Scanner AST (analyse comportementale)**

Au lieu de chercher des strings comme "setup_bun.js" (fragile, l'attaquant change les noms), on analyse le comportement du code :

```javascript
// Patterns comportementaux detectes
- eval() / new Function()      // Execution dynamique
- child_process.exec/spawn     // Commandes shell
- fs.readFileSync('.npmrc')    // Vol credentials
- process.env.NPM_TOKEN        // Acces tokens
- https.request + process.env  // Exfiltration
```

**2. Systeme IOC (Indicators of Compromise)**

Integration des IOCs publies par Datadog, Wiz, JFrog :
- Noms de packages malveillants
- Hashes SHA256 des payloads
- Marqueurs textuels ("Sha1-Hulud", "The Second Coming")
- Fichiers suspects (setup_bun.js, bun_environment.js)

**3. Playbooks de Reponse**

Chaque type de menace a une recommandation actionnable :
```
lifecycle_script : "Verifier le script. Desactiver avec npm config set ignore-scripts true"
known_malicious  : "CRITIQUE: Supprimer immediatement. Regenerer tous les tokens."
```

#### Commits du Jour 1
- `init: MUAD'DIB npm security scanner`
- `feat: AST analysis with acorn`
- `feat: IOC integration from Datadog/Wiz`
- `feat: CLI with scan/update/watch commands`
- `feat: GitHub Actions CI/CD`

---

### Jour 2 - 2 janvier 2026 : Features Avancees

#### Mode --explain avec MITRE ATT&CK

Chaque menace est maintenant mappee sur le framework MITRE ATT&CK :

```
T1059.007 - Command and Scripting Interpreter: JavaScript
T1195.002 - Supply Chain Compromise: Software Supply Chain
T1552.001 - Unsecured Credentials: Credentials In Files
T1041     - Exfiltration Over C2 Channel
```

#### Export SARIF pour GitHub Security

Format standard pour integration native dans GitHub Security tab :

```bash
muaddib scan . --format sarif > results.sarif
```

#### Analyse Dataflow

Detection des flux credential vers exfiltration :
```javascript
// Detecte : fs.readFile('.npmrc') puis https.request()
// Pattern : lecture credentials + envoi reseau = CRITIQUE
```

#### Premiere Publication npm

```bash
npm publish
# muaddib@1.0.0 publie !
```

---

### Jour 3 - 3 janvier 2026 : Typosquatting + Scoring

#### Detection Typosquatting (Levenshtein)

Beaucoup d'attaques utilisent des noms similaires aux packages populaires :
- `lodahs` au lieu de `lodash`
- `axois` au lieu de `axios`
- `expres` au lieu de `express`

Implementation avec distance de Levenshtein :
```javascript
// Distance 1 = tres suspect (lodahs/lodash)
// Distance 2 = suspect si package populaire >= 5 chars
```

#### Systeme de Scoring 0-100

Plus intuitif qu'une liste de menaces :
```
0-20   = LOW (safe)
21-40  = MEDIUM (a verifier)
41-70  = HIGH (problemes)
71-100 = CRITICAL (danger)
```

Calcul base sur severite et nombre de menaces :
```javascript
score = somme(menace.severity * poids) 
// CRITICAL=25, HIGH=15, MEDIUM=8, LOW=3
```

#### Webhooks Discord/Slack

Notifications en temps reel pour les equipes :
```bash
muaddib scan . --webhook https://discord.com/api/webhooks/...
```

#### Publication v1.0.3

```bash
npm version patch && npm publish
```

---

### Jour 4 - 3 janvier 2026 (soir) : Extension VS Code

#### Marketplace Publication

L'extension VS Code permet :
- Scan automatique a l'ouverture d'un projet
- Indicateurs dans la barre de statut
- Diagnostics inline dans package.json
- Commandes palette (Ctrl+Shift+P)


#### Scraper Multi-Sources

Automatisation de la collecte d'IOCs depuis :
1. Shai-Hulud 2.0 Detector (GitHub)
2. Datadog Security Labs
3. Socket.dev reports
4. Phylum Research
5. npm removed packages

```bash
muaddib scrape  # Met a jour la base IOCs
```

---

### Jour 5-7 - 8 janvier 2026 : Validation et Polish

#### Probleme : Trop de Faux Positifs

En testant sur des vrais projets (React, Vue, Express), j'ai decouvert des centaines de fausses alertes :

| Package | Faux Positif | Raison |
|---------|-------------|--------|
| vite | lifecycle_script | Build tool legitime |
| esbuild | spawn() detection | Bundler natif |
| sharp | postinstall | Compilation binaire |

#### Solutions Implementees

**1. Whitelists contextuelles**
```javascript
const TRUSTED_PACKAGES = ['esbuild', 'sharp', 'bcrypt', ...];
const SAFE_FILES = { 
  'inject.js': ['async', 'asynckit'],  // Faux positif connu
  'install.js': ['esbuild', 'sharp']   // Scripts de build
};
```

**2. Ajustement detection typosquat**
```javascript
// Avant : distance 2 si package >= 8 chars
// Apres : distance 2 si package >= 5 chars
// Permet de detecter lodahs (6 chars) et axois (5 chars)
```

**3. Retrait GitHub Advisory**

GitHub Advisory inclut des CVE/vulnerabilites, pas du malware. Ca generait des faux positifs sur des packages comme `qs` (querystring parser d'Express).

```javascript
// Retire du scraper - MUAD'DIB = anti-malware, pas scanner CVE
// Utiliser npm audit ou Snyk pour les vulnerabilites
```

#### Ajout Shai-Hulud v3 (28 decembre 2025)

Nouvelle variante decouverte pendant le developpement :
- Package : `@vietmoney/react-big-calendar@0.26.2`
- Nouveaux fichiers : `bun_installer.js`, `environment_source.js`
- Nouveau marqueur : "Goldox-T3chs: Only Happy Girl"

Ajoutes dans `iocs/builtin.yaml`.

#### Externalisation Configuration

Tout le hardcoding deplace vers des fichiers config :
- `iocs/builtin.yaml` : IOCs de fallback (offline)
- `data/static-iocs.json` : Sources statiques (Socket, Phylum)
- `iocs/packages.yaml` : IOCs YAML community

---

## Resultats Finaux

### Tests
```
42/42 tests passants
Score React.js : 3/100 (LOW) - 1 alerte legitime
Score Express app : 0/100 (CLEAN)
```

### Metriques
- **930 packages malveillants** dans la base IOCs
- **8 sources** de threat intelligence
- **42 tests** automatises
- **~2500 lignes** de code JavaScript

### Publications
- **npm** : `muaddib` v1.0.6
- **VS Code Marketplace** : v1.0.6
- **GitHub** : github.com/DNSZLSK/muad-dib

---

## Stack Technique

| Composant | Technologie | Justification |
|-----------|-------------|---------------|
| Runtime | Node.js | Ecosysteme npm natif |
| Parser AST | acorn + acorn-walk | Leger, standard, fiable |
| Hashing | crypto (natif) | SHA256 pour IOCs |
| Config | YAML + JSON | Lisible, editable |
| CLI | Commander.js | Standard npm CLI |
| Tests | Custom runner | Simple, pas de deps |
| CI/CD | GitHub Actions | Integration native |

---

## Apprentissages

### Techniques

1. **Analyse AST** - Parser du JavaScript pour comprendre son comportement, pas juste chercher des strings
2. **Distance de Levenshtein** - Algorithme pour detecter les typosquats
3. **MITRE ATT&CK** - Framework standard pour classifier les menaces
4. **SARIF** - Format d'echange pour outils de securite
5. **Scraping ethique** - Collecter des IOCs depuis des sources publiques

### Methodologie

1. **MVP first** - Commencer simple, iterer. L'IA prevue au depart a ete reportee.
2. **Test sur le reel** - Scanner des vrais projets (React, Vue) revele les faux positifs
3. **Feedback loop** - Chaque faux positif ameliore les whitelists
4. **Documentation inline** - Les playbooks expliquent chaque menace

### Ecosysteme Securite npm

- **Socket.dev** - Leader detection comportementale
- **Snyk** - Vulnerabilites + licence
- **Phylum** - Research malware
- **Aikido** - Threat intel (ils m'ont repondu sur Reddit !)

---

## Evolutions Futures

### Court Terme
- Mode `--fix` pour appliquer automatiquement les corrections
- Support pnpm et yarn natif
- Dashboard web local

### Moyen Terme
- API REST pour integration CI/CD custom
- Base IOCs communautaire (contributions)
- Analyse des lockfiles (diff entre versions)

### Long Terme
- ML pour detecter patterns inconnus
- Sandbox d'execution (comme Socket)
- Extension navigateur (npm website)

---

## Reflexions Personnelles

Ce projet m'a fait realiser que la securite supply-chain est un domaine ou un developpeur solo peut avoir un impact reel. Les outils commerciaux (Socket, Snyk) coutent cher et ne sont pas accessibles a tous.

MUAD'DIB n'est pas parfait - c'est un "weekend project" compare a Socket qui a des millions de funding. Mais il est **gratuit**, **open source**, et **fonctionne** pour detecter les menaces connues comme Shai-Hulud.

Le plus satisfaisant : voir le score passer de 126 alertes (faux positifs) a 1 alerte legitime sur le repo React.js apres une semaine d'iterations.

---

## Liens

- **npm** : https://www.npmjs.com/package/muaddib
- **Datadog IOCs** : https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/
- **Aikido Blog** : https://www.aikido.dev/blog/shai-hulud-strikes-again---the-golden-path

---

*Redige le 8 janvier 2026*  
*"Fear is the mind-killer. I will face my fear."* - Dune
