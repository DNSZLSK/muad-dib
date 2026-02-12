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

### Le sandbox Docker

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
    rev: v1.4.1
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

---

## Etat actuel

### Ce qui fonctionne

| Feature | Détails |
|---------|---------|
| CLI complète | scan, watch, update, scrape, install, safe-install, daemon, sandbox, **diff**, **init-hooks**, **remove-hooks** |
| Base IOCs | 225 000+ npm + 14 000+ PyPI packages malveillants |
| Détection Shai-Hulud | v1, v2, v3 couverts |
| Exports | JSON, HTML, SARIF |
| Extension VS Code | Publiée sur Marketplace |
| Webhooks | Discord / Slack (envoi uniquement si menaces détectées) |
| Docker Sandbox | Analyse comportementale isolée (strace, tcpdump, filesystem diff, DNS/HTTP/TLS capture, 16 patterns exfiltration, mode strict iptables) |
| GitHub Actions Backdoor | Détection discussion.yaml (Shai-Hulud 2.0) |
| **Diff entre versions** | Compare et montre uniquement les NOUVELLES menaces |
| **Pre-commit hooks** | Support pre-commit, husky, git natif |
| **GitHub Action Marketplace** | Avec inputs/outputs et SARIF auto |
| Version check | Notification automatique des nouvelles versions au demarrage |
| Tests | **296 tests unitaires** + 56 fuzz + 15 adversariaux, **80% coverage** (Codecov) |
| Audit securite | 2 audits complets, **58 issues corrigees**, [rapport PDF](MUADDIB_Security_Audit_Report_v1.4.1.pdf) |

### Ce qui manque (honnêtement)

**Pas de ML/machine learning** : L'analyse repose sur des patterns statiques et des IOCs connus. Un attaquant qui obfusque différemment peut passer à travers.

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

MUAD'DIB n'est pas parfait. C'est un projet de formation, pas un produit enterprise. Mais il fonctionne pour ce qu'il est censé faire : détecter les menaces npm et PyPI connues, analyser les comportements suspects dans un sandbox, et guider la réponse.

Le plus satisfaisant : voir le score passer de 126 alertes (faux positifs) à 1 alerte légitime sur React.js après une semaine d'itérations. Et voir le sandbox Docker fonctionner du premier coup (après avoir fixé les permissions).

*"Fear is the mind-killer. I will face my fear."* - Dune, Frank Herbert
