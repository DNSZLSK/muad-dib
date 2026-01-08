# Carnet de Bord - Projet MUAD'DIB

**Scanner de sécurité npm contre les attaques supply-chain**

DNSZLSK  
Formation CDA - AFPA  
Janvier 2026

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

**1. Matching IOC** : Une base de 930+ packages malveillants connus. Si ton projet en utilise un, alerte immédiate.

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

---

## Ce que j'ai appris

### Techniquement

**Analyse AST avec acorn** : Parser du JavaScript pour comprendre son comportement, pas juste chercher des strings. Un `eval()` dans un fichier de config n'a pas la même signification qu'un `eval()` dans un postinstall.

**Distance de Levenshtein** : L'algorithme classique pour mesurer la similarité entre deux chaînes. Parfait pour détecter `axois` qui essaie de se faire passer pour `axios`.

**MITRE ATT&CK** : Le framework de référence pour classifier les techniques d'attaque. Chaque détection de MUAD'DIB est mappée sur une technique (T1195.002 pour supply chain, T1552.001 pour vol de credentials, etc.).

**SARIF** : Le format standard pour les résultats de scanners de sécurité. Permet l'intégration native dans GitHub Security.

**Publication npm et VS Code Marketplace** : Tout le workflow : versioning, 2FA, tokens, métadonnées.

### Humainement

Ce projet m'a fait réaliser qu'un dev solo peut avoir un impact réel en sécurité. Les outils commerciaux coûtent cher. Socket c'est gratuit pour l'open source, mais les features avancées sont payantes. MUAD'DIB ne les remplacera jamais, mais il offre une première ligne de défense gratuite.

J'ai aussi appris à être honnête sur les limites d'un projet. MUAD'DIB détecte les menaces *connues*. Pour les zero-day, il faut des outils qui font de l'analyse dynamique, du sandboxing, des trucs qui demandent des ressources que je n'ai pas.

---

## État actuel

### Ce qui fonctionne

| Feature | Détails |
|---------|---------|
| CLI complète | scan, watch, update, scrape, daemon |
| Base IOCs | 930+ packages malveillants |
| Détection Shai-Hulud | v1, v2, v3 couverts |
| Exports | JSON, HTML, SARIF |
| Extension VS Code | Publiée sur Marketplace |
| Webhooks | Discord / Slack |
| Tests | 42 tests passants |

### Ce qui manque (honnêtement)

**Pas de sandboxing** : Je ne lance jamais le code suspect. Socket le fait, c'est pour ça qu'ils peuvent détecter des comportements que je ne vois pas.

**Pas de ML** : Mon analyse AST cherche des patterns codés en dur. Un attaquant qui obfusque différemment peut passer à travers.

**Dépendance aux sources tierces** : Si Datadog change son API, mon scraper casse.

---

## Liens

- **npm** : npmjs.com/package/muaddib-scanner
- **GitHub** : github.com/DNSZLSK/muad-dib
- **VS Code** : marketplace.visualstudio.com/items?itemName=dnszlsk.muaddib-vscode
- **Discord** : discord.gg/y8zxSmue

---

## Conclusion

MUAD'DIB n'est pas parfait. C'est un projet de formation, pas un produit enterprise. Mais il fonctionne pour ce qu'il est censé faire : détecter les menaces npm connues et guider la réponse.

Le plus satisfaisant : voir le score passer de 126 alertes (faux positifs) à 1 alerte légitime sur React.js après une semaine d'itérations. C'est ça, le développement : tester, échouer, corriger, recommencer.

Pour la v2, j'aimerais ajouter une vraie analyse dataflow et peut-être un mode sandbox minimal. On verra.

*"Fear is the mind-killer. I will face my fear."* - Dune, Frank Herbert
