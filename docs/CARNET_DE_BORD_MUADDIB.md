# Carnet de Bord - Projet MUAD'DIB

**Scanner de securite npm & PyPI contre les attaques supply-chain**

DNSZLSK
Formation CDA - AFPA
Janvier - Mars 2026

---

## D'ou vient ce projet ?

Novembre 2025. Je scrolle Reddit, section r/netsec. Un post attire mon attention : **"Shai-Hulud 2.0 : un ver npm a compromis 796 packages"**.

Je clique. Et la, je decouvre l'ampleur du truc.

Ce ver, baptise Shai-Hulud comme les vers geants de Dune, s'est propage automatiquement via les dependances npm. Il volait les tokens GitHub, npm, AWS, et les exfiltrait vers des repos publics marques "Sha1-Hulud: The Second Coming". Plus de 25 000 depots GitHub touches. Des boites comme Zapier, PostHog, Postman temporairement compromises.

Je me suis dit : "Et si je creais un outil pour detecter ca ?"

Pas pour concurrencer les gros. Socket, Snyk, ils ont des millions de funding et des equipes de 50 personnes. Juste pour avoir quelque chose de gratuit, open source, que n'importe quel dev peut installer en une commande.

Le nom s'est impose naturellement : **MUAD'DIB**, le nom Fremen de Paul Atreides dans Dune, celui qui combat les vers geants.

---

## Premiere semaine : la base

### L'erreur du debutant

Mon premier reflexe a ete de vouloir faire du machine learning. Entrainer un modele pour detecter les patterns malveillants. Claude m'a recadre direct :

> "Oublie l'IA pour la v1. Concentre-toi sur l'analyse AST des comportements et l'integration des IOCs existants. C'est moins sexy mais c'est ce qui protege reellement."

Il avait raison. Les attaquants de Shai-Hulud utilisent des patterns connus. Pas besoin de reinventer la roue.

### Ce que j'ai construit

Trois piliers :

**1. Matching IOC** : Une base de 225 000+ packages malveillants connus. Si ton projet en utilise un, alerte immediate.

**2. Analyse AST** : Je parse le JavaScript avec acorn pour detecter les patterns suspects : `eval()`, `child_process`, lecture de `.npmrc`, etc.

**3. Detection typosquatting** : Distance de Levenshtein pour reperer les noms similaires aux packages populaires (`lodahs` vs `lodash`).

---

## Les galeres

### 126 alertes sur React.js

Premier test sur le repo officiel de React. Resultat : **126 alertes**. Score de risque : 89/100.

Evidemment, React n'est pas un malware. Mon scanner detectait des trucs legitimes comme des faux positifs.

Exemples de ce qui declenchait des alertes :

| Package | Detection | Realite |
|---------|-----------|---------|
| esbuild | child_process.spawn() | Bundler natif legitime |
| sharp | postinstall script | Compilation binaire necessaire |
| qs | IOC GitHub Advisory | CVE (vulnerabilite), pas malware |

J'ai passe trois jours a affiner les whitelists. Resultat final sur React : **1 alerte legitime** (un script postinstall de build). Score : 3/100.

### Le scraper qui casse

J'ai voulu automatiser la collecte d'IOCs depuis plusieurs sources : Datadog, Socket, Phylum, OSV, GitHub Advisory. Sauf que GitHub Advisory inclut des CVE (vulnerabilites), pas du malware.

Resultat : 54 faux positifs d'un coup. Le package `qs` (utilise par Express) etait flague comme malveillant alors qu'il avait juste une CVE corrigee depuis longtemps.

J'ai du retirer GitHub Advisory du scraper. MUAD'DIB est un scanner **anti-malware**, pas un scanner de vulnerabilites. Pour les CVE, il y a `npm audit` ou Snyk.

### Le sandbox Docker (analyse dynamique)

Apres l'analyse statique, j'ai voulu aller plus loin : executer le code suspect dans un environnement isole pour voir ce qu'il fait vraiment.

Le principe est simple :
1. Creer un container Docker ephemere
2. Installer le package dedans avec `npm install`
3. Capturer les comportements avec `strace` et `tcpdump`
4. Analyser : connexions reseau, acces fichiers sensibles, process suspects

Premier test sur `lodash` : aucun comportement suspect. Normal, c'est clean.

Le piege ? Les faux positifs. Mon premier scanner detectait "nc" (netcat) dans le nom de fichier `graceful-fs/clone.js`. J'ai du affiner la detection pour chercher `/nc ` ou `netcat` en commande, pas en substring.

Le sandbox ne remplace pas Socket ou Aikido qui font ca a grande echelle avec du ML. Mais pour un dev qui veut verifier un package inconnu avant de l'installer, c'est deja ca.

---

## Ce que j'ai appris

### Techniquement

**Analyse AST avec acorn** : Parser du JavaScript pour comprendre son comportement, pas juste chercher des strings. Un `eval()` dans un fichier de config n'a pas la meme signification qu'un `eval()` dans un postinstall.

**Distance de Levenshtein** : L'algorithme classique pour mesurer la similarite entre deux chaines. Parfait pour detecter `axois` qui essaie de se faire passer pour `axios`.

**MITRE ATT&CK** : Le framework de reference pour classifier les techniques d'attaque. Chaque detection de MUAD'DIB est mappee sur une technique (T1195.002 pour supply chain, T1552.001 pour vol de credentials, etc.).

**SARIF** : Le format standard pour les resultats de scanners de securite. Permet l'integration native dans GitHub Security.

**Docker et sandboxing** : Creer des containers ephemeres pour analyser du code suspect. Utiliser `strace` pour tracer les appels systeme, `tcpdump` pour capturer le reseau.

**Publication npm et VS Code Marketplace** : Tout le workflow : versioning, 2FA, tokens, metadonnees.

### Humainement

Ce projet m'a fait realiser qu'un dev solo peut avoir un impact reel en securite. Les outils commerciaux coutent cher. Socket c'est gratuit pour l'open source, mais les features avancees sont payantes. MUAD'DIB ne les remplacera jamais, mais il offre une premiere ligne de defense gratuite.

J'ai aussi appris a etre honnete sur les limites d'un projet. MUAD'DIB detecte les menaces *connues*. Pour les zero-day, il faut des outils qui font de l'analyse dynamique avancee, du ML, des trucs qui demandent des ressources que je n'ai pas.

---

## Audit et optimisations (Janvier 2026)

Apres la v1.2.5, j'ai demande a Claude Code de faire un audit complet. Le constat etait sans appel : techniquement solide mais pas "production-ready". Pas de visibilite (pas de badges GitHub), aucune feature differenciante, pas de metriques de coverage.

J'ai commence par les fondations : **parallelisation des scanners** avec `Promise.all()`, remplacement des tableaux par des `Map`/`Set` pour les lookups IOC (O(n) vers O(1)), cache SHA256, protection symlinks, fix XSS dans les rapports HTML.

La feature dont je suis le plus fier de cette periode : **`muaddib diff`**. Compare les menaces entre la version actuelle et un commit precedent, et affiche uniquement les NOUVELLES menaces. En vrai, les projets ont de la dette technique de securite. Avec `muaddib diff`, tu peux bloquer un PR uniquement s'il introduit de nouveaux problemes.

J'ai aussi ajoute le support pre-commit (pre-commit framework, husky, git natif) et publie la GitHub Action sur le Marketplace.

---

## Hardening et tests (Fevrier 2026)

Deux passes d'audit securite sur les 27 fichiers source ont revele 58 issues. Les plus graves : YAML unsafe loading (tags `!!js/function` executables), SSRF dans le fetcher IOC (redirects non validees), 18 regles manquantes dans `rules/index.js`. Coverage montee de 52% a 80%.

En parallele, j'ai cree une suite de **56 fuzz tests** pour verifier que les parsers ne crashent jamais (YAML invalide, billion laughs, JSON avec 10 000 cles, AST avec 100 niveaux de callbacks, CLI avec injection `$(...)`) et **15 scenarios adversariaux** simulant des packages malveillants realistes. 15/15 detectes.

---

## Support Python/PyPI (Fevrier 2026)

Apres npm, j'ai etendu MUAD'DIB pour scanner les projets Python. Le scanner parse `requirements.txt` (y compris les `-r` recursifs), `setup.py` et `pyproject.toml` (PEP 621 et Poetry). La base IOC integre le dump OSV PyPI avec ~14 000 packages malveillants (MAL-*).

Le vrai defi technique etait la distribution. Le fichier `iocs.json` complet faisait 112 MB apres scraping de toutes les sources. Impossible a distribuer via npm (limite 10 MB). J'ai cree un format compact (`iocs-compact.json`, ~5 MB) ou 87% des packages sont stockes comme wildcards (toutes versions malveillantes) et les 13% restants comme entrees versionnees. Au chargement, tout est converti en `Map`/`Set` pour des lookups instantanes.

---

## Le moniteur zero-day (13 Fevrier 2026)

MUAD'DIB savait scanner des projets existants, mais pas surveiller les nouveaux packages en temps reel. Les attaques supply-chain se propagent en heures. Le temps de faire un `muaddib scan` manuellement, c'est deja trop tard.

J'ai construit un moniteur continu qui interroge les registres npm et PyPI, telecharge et scanne chaque nouveau package, et envoie des alertes Discord en temps reel. Les galeres techniques ont ete nombreuses : l'endpoint npm deprecie (migration vers le flux RSS), les crashs PyPI ECONNREFUSED (l'URL du tarball etait `null`), le webhook Discord qui retournait 400 parce que les champs du summary ne correspondaient pas.

Sur une journee, le moniteur scanne ~2000-3000 packages. Les alertes arrivent avec suffisamment de contexte pour prendre une decision rapide.

---

## v2.0 - Le changement de paradigme (13 Fevrier 2026)

MUAD'DIB v1 etait 100% reactif. Si une attaque n'etait pas dans la base IOC, elle passait a travers. Les attaques comme ua-parser-js (2021) ou event-stream (2018) ont ete detectees des heures ou des jours apres la compromission. Pendant ce temps, des milliers de devs avaient deja installe les versions malveillantes.

En etudiant comment Socket.dev et Phylum detectent les 0-days, j'ai identifie un pattern commun : **l'analyse comportementale entre versions**. Au lieu de chercher si un package est dans une liste noire, on compare ce qui a change entre la version N et la version N-1.

J'ai implemente 5 features :
1. **Lifecycle soudain** : un package qui n'avait jamais de `postinstall` en ajoute un soudainement
2. **Diff AST temporel** : APIs dangereuses nouvellement ajoutees (child_process, eval, fetch)
3. **Anomalie de publication** : rafales de versions en 24h, package dormant avec une release soudaine
4. **Changement de maintainer** : le pattern event-stream (seul maintainer remplace)
5. **Canary tokens** : de faux credentials injectes dans le sandbox pour pieger les malwares qui les exfiltrent

En parallele, j'ai refactore les tests d'un seul fichier de 4000 lignes en 16 fichiers modulaires. Passage de 370 a 541 tests.

---

## Le Red Team (Fevrier - Mars 2026)

C'est le chapitre le plus humiliant et le plus formateur de tout le projet.

Le principe : creer des packages malveillants evasifs avec les regles gelees, mesurer combien passent a travers, puis corriger les angles morts. Le score pre-tuning (avant correction) est la metrique la plus honnete : elle mesure la capacite de generalisation.

**Vague 1 (20 samples)** : Baseline catastrophique. TPR 0%, ADR 14%. Le scanner ne detectait quasiment rien. Corrections massives du scanner AST, du dataflow, du package scanner. 5 nouvelles regles. Resultat post-fix : 20/20.

**Vague 2 (5 samples)** : Template literal obfuscation, proxy env intercept, websocket exfil. Score pre-tuning : 0%. Les techniques etaient completement hors radar.

**Vague 3 (5 samples)** : Techniques reelles 2025-2026. AI agent weaponization (pattern s1ngularity), injection de prompts dans .cursorrules, zero-deps dropper (pattern PhantomRaven), exfiltration via webhook Discord, preinstall avec fork detache. Score pre-tuning : 60%. J'ai du creer un 13eme scanner dedie a la detection d'injection dans les fichiers de configuration d'agents IA.

Puis les holdouts, qui revelent la vraie capacite de generalisation :

| Batch | Pre-tuning | Tendance |
|-------|------------|----------|
| Holdout v1 | 30% (3/10) | Angles morts massifs |
| Holdout v2 | 40% (4/10) | Amelioration marginale |
| Holdout v3 | 60% (6/10) | Amelioration significative |
| Holdout v4 | 80% (8/10) | La desobfuscation generalise |
| Holdout v5 | 50% (5/10) | Nouveau scanner inter-module |

Le 30% du holdout v1 a ete une gifle. Chaque vague revele des techniques que les regles existantes ne couvrent pas. Mais la tendance 30% → 40% → 60% → 80% montre que chaque correction ameliore la generalisation au-dela des patterns specifiques corriges.

La derniere campagne (Vague 4, mars 2026) a ete la pire : 0/5. Des techniques d'evasion simples mais efficaces. `.gi` + `t` contourne tout pattern matching sur `.git`. Un `new Function()` qui ne settait pas le flag `hasDynamicExec`. Des chemins construits via retour de fonction au lieu de variables. La concatenation de strings est une technique d'evasion redoutablement simple, et elle a ete documentee dans des campagnes reelles (SANDWORM_MODE).

Au total : 107 samples adversariaux (67 crees + 40 holdouts), ADR 96.3% (103/107). Les 4 misses sont documentes et acceptes.

---

## Voir a travers l'obfuscation (20 Fevrier 2026)

MUAD'DIB detectait les patterns d'obfuscation (variables `_0x`, hex escapes, base64) mais ne pouvait pas **voir a travers**. Un `require('child' + '_process')` etait detecte comme concatenation suspecte, mais un `require(String.fromCharCode(99,104,105,108,100,95,112,114,111,99,101,115,115))` passait completement inapercu.

J'ai cree un moteur de desobfuscation statique (`src/scanner/deobfuscate.js`) qui transforme le code obfusque en code lisible sans jamais l'executer. 4 transformations : string concat folding, charcode reconstruction, base64 decode, hex array resolution, plus une propagation de constantes qui les enchaine.

La lecon la plus importante : mon premier reflexe a ete de remplacer le code original par le code desobfusque avant le scan. **Mauvaise idee.** Le sample `dynamic-require` est passe de score 78 a 28 parce que les signaux d'obfuscation eux-memes (qui sont suspects) etaient perdus. La bonne approche est **additive** : scanner l'original d'abord, puis le desobfusque, et ajouter uniquement les nouvelles findings.

L'impact mesure sur le holdout v4 etait spectaculaire. `hex-array-exec` : totalement invisible sans desobfuscation (score 0 → 25). `mixed-obfuscation-stealer` : les couches d'obfuscation masquaient les patterns dangereux (score 10 → 45).

---

## Le dataflow inter-module (20 Fevrier 2026)

Les attaquants le savent : il suffit de separer la lecture des credentials dans `reader.js` et l'exfiltration dans `sender.js` pour echapper a un scanner qui ne regarde qu'un fichier a la fois.

J'ai cree `src/scanner/module-graph.js` qui construit un graphe de dependances entre les modules d'un package et propage les teintes a travers les frontieres de fichiers. L'analyse supporte les re-exports (3 hops max), les methodes de classe, les named exports, et meme les instances importees.

Deux limitations acceptees et documentees : les EventEmitters (pub/sub entre modules) et les callbacks (propagation de teinte a travers les fonctions anonymes). Ces deux cas necessitent une analyse dynamique ou symbolique qui depasse le scope de l'analyse statique. Mais ils n'affectent pas les patterns inter-modules les plus courants dans les malwares supply-chain.

Plus tard (v2.6.0-v2.6.1), j'ai aussi ajoute un **graphe d'intention** pour la coherence source-sink intra-fichier, et etendu le module-graph pour supporter les instances de classe (`this.X`), les pipelines stream, et les EventEmitters. Une decision architecturale importante : la co-occurrence cross-file sans preuve de data flow a ete volontairement exclue apres des tests sur 529 packages benins qui ont montre une explosion de faux positifs.

---

## Le jour ou j'ai decouvert le vrai FPR (20 Fevrier 2026)

C'est le moment le plus embarrassant du projet.

En examinant le code de `evaluateBenign()`, j'ai realise que le **FPR de 0%** etait completement faux. La fonction creait des repertoires temporaires vides contenant uniquement un `package.json` avec le nom du package. Les 13 scanners n'avaient litteralement rien a analyser. Le 0% ne mesurait que le matching IOC et la detection de typosquatting sur les noms, pas la capacite du scanner a eviter les faux positifs sur du vrai code source.

J'ai reecrit `evaluateBenign()` pour telecharger et scanner les vrais tarballs npm (529 packages). Premier resultat : **38% de faux positifs** (19/50 sur les premiers packages). Next.js a 76 `dynamic_require`, Restify a 52 `prototype_hook`, Gatsby a du hot-reload avec `require.cache`. Ce sont tous des patterns qui se superposent avec les techniques malware.

**Ne jamais faire confiance a un FPR de 0%.** Un scanner qui ne genere aucun faux positif ne scanne probablement rien.

Ce qui a suivi a ete un marathon de reduction du FPR. L'observation cle : les packages legitimes produisent des volumes massifs de certains types de menaces (Next.js a 76 dynamic requires), alors que les malwares n'en ont que 1 a 3. Un malware est furtif. Un framework est bruyant.

J'ai implemente des seuils de volume : si un package a plus de 10 `dynamic_require`, tous passent LOW. Si plus de 5 `dangerous_call_function`, tous passent LOW. Des whitelists pour les env vars de configuration (`npm_config_*`, `NODE_ENV`), les fichiers dans `dist/` traites comme du code bundle, un cap sur les `prototype_hook` MEDIUM.

Chaque correction ciblait un type specifique avec un seuil conservatif. Chaque correction etait verifiee sur les 40 holdouts adversariaux (zero regression). Le FPR est descendu : 38% → 19.4% → 17.5% → ~13%.

Le levier le plus puissant a ete le **scoring per-file max** : au lieu d'additionner les findings de tous les fichiers, le score est le maximum d'un fichier individuel plus les menaces package-level. Un framework avec 500 fichiers .js ne depasse plus le seuil juste parce que chaque fichier a un petit finding. Resultat : FPR de 13% → ~7%.

Apres les audits de securite qui ont resserre les heuristiques (FPR remonte a ~13.6%), puis les passes P5/P6 de precision : FPR curated ~10.8%, FPR random 7.5%. C'est honnete. Les FP restants sont des cas ambigus (fetch + eval dans un template engine, compilateurs monolithiques minifies) qui ne peuvent pas etre resolus par des heuristiques.

---

## Ground truth : de 4 a 49 samples (Fevrier 2026)

Au debut, le ground truth etait de 4 attaques reelles (event-stream, ua-parser-js, coa, node-ipc). TPR 100%. Facile.

J'ai elargi a 51 echantillons d'attaques reelles (49 actifs) couvrant 2018-2025 : eslint-scope, flatmap-stream, solana-web3js, rc, getcookies, ledgerhq-connect-kit, shai-hulud, et 39 autres. 3 nouvelles regles de detection ont ete necessaires : `crypto_decipher` (pattern flatmap-stream), `module_compile` (execution de code en memoire), et les proprietes `.secretKey`/`.privateKey` (pattern solana-web3js).

Le TPR est passe de 100% a 93.9% (46/49). Pas par regression, mais par expansion : les 3 misses sont hors scope (attaques browser-only comme lottie-player, polyfill-io, trojanized-jquery). Avec 49 samples, 93.9% est un chiffre beaucoup plus representatif que le 100% sur 4 samples.

En parallele, le coverage a ete pousse de 72% a 86% avec une expansion massive de la suite de tests (862 → 1317 tests). Les 40 holdouts ont ete fusionnes dans l'evaluation ADR : 75/75, puis 78/78 avec 3 samples supplementaires.

---

## Les audits de securite (Mars 2026)

Le projet a subi plusieurs vagues d'audit tout au long de son developpement. En tout, plus de 140 issues corrigees : injections de commande, SSRF, prototype pollution, YAML unsafe, race conditions HMAC, ReDoS dans les regex, fuites de spinner, ecritures non-atomiques.

Le plus gros audit (v2.5.0-v2.5.6) a traite 41 issues en 5 releases. Chaque vague de correction etait conservative : on corrige, on teste, on verifie zero regression, on continue.

L'audit post-sécurité (v2.6.5-v2.6.9) a ete particulierement structurant. Parmi les changements : suppression de la self-dependency (MUAD'DIB ne se scanne plus lui-meme), garde anti-recursion dans le dataflow (MAX_TAINT_DEPTH=50), seuil ADR global unique (suppression des seuils par echantillon), et mode paranoid avec tracking des alias eval/Function/require.

Un dernier audit (v2.10.1) a identifie 6 bypasses exploitables. Session intensive de 24h : WebSocket/MQTT comme sinks, entropie fragmentee, destructuring + chaine de prototypes, dilution `dynamic_require`, bruit `env_access`, correlation lifecycle-file. Tous fermes, zero regression.

Le trade-off constant : les heuristiques plus strictes ameliorent la detection mais augmentent le FPR. Le FPR est remonte de 6% a ~13.6% apres les hardening v2.5.13-v2.5.14, puis redescendu a ~10.8% apres les passes de precision P5/P6.

---

## Le moniteur en production (Mars 2026)

Le moniteur a evolue significativement entre la v1 et la v2.8.

Le changement le plus important : le remplacement du polling RSS par le **changes stream CouchDB** de npm. L'ancien moniteur interrogeait le RSS toutes les 60 secondes avec un delai de 1-2 minutes et des publications manquees si plus de 50 packages etaient publies dans la fenetre. Le changes stream est un flux continu en temps reel, sans omission.

Les galeres : HTTP 400 au demarrage (le `since` initial doit etre le `update_seq`, pas "now"), reconnection avec backoff exponentiel, scan parallele (concurrency=3).

Reduction du bruit webhook en 4 chantiers : self-exclude (ne pas scanner `muaddib-scanner` lui-meme), scope grouping (un monorepo qui publie 20 packages en rafale genere une seule alerte), WASM standalone (WebAssembly sans reseau n'est pas suspect), reputation scoring (facteur base sur l'age, les versions, et les telechargements).

Le sandbox a aussi evolue : simulation de 6 environnements CI (certains malwares ne s'activent que si `CI=true`), canary tokens enrichis (6 honeypots), et surtout le **monkey-patching preload**. Le preload intercepte `Date.now()`, `setTimeout`, et toutes les APIs sensibles. Si un malware attend 72h avant de voler les credentials, on lui fait croire que 72h se sont ecoulees. Multi-run a 0h, 72h, et 7 jours.

---

## GlassWorm et la blockchain C2 (18 Mars 2026)

Mars 2026 : decouverte de la campagne GlassWorm. 433+ packages npm compromis utilisant deux techniques inedites.

La premiere : des **caracteres Unicode invisibles**. Le code malveillant est cache dans des caracteres zero-width (U+200B, U+200C, U+200D), des BOM hors position 0, des variation selectors. Le fichier semble vide a l'oeil nu mais contient du code executable.

La deuxieme : du **C2 via blockchain Solana**. Au lieu d'un serveur C2 classique (facile a takedown), les attaquants stockent les commandes dans des transactions Solana. Le malware lit les instructions via `getSignaturesForAddress`. Le serveur C2 est la blockchain elle-meme, immuable et impossible a saisir.

J'ai ajoute la detection Unicode invisible dans le scanner d'obfuscation (seuil >= 3 caracteres invisibles), la detection blockchain C2 dans le scanner AST (import Solana + methodes C2), et les endpoints RPC hardcodes (Solana, Infura, Ankr). 6 IPs C2 GlassWorm ajoutees aux domaines suspects, 8 packages compromis ajoutes aux IOC builtin.

Le moniteur a aussi ete renforce a ce moment : IOC pre-check avant tout download (webhook PRE-ALERT immediat), extraction du tarball URL directement depuis le doc CouchDB (plus de 404 quand npm supprime le package), et cache local des tarballs pour les packages a haute priorite.

---

## Le compound scoring (19 Mars 2026)

En analysant les co-occurrences de types de menaces dans les packages benins vs malveillants, j'ai identifie des combinaisons qui n'apparaissent **jamais** dans les 529 packages benins mais sont frequentes dans les malwares. Exemples : `lifecycle_script` + `typosquat_detected` (script lifecycle sur un package typosquat), ou `staged_binary_payload` + `crypto_decipher` (payload chiffre + execution).

Le systeme injecte des findings CRITICAL synthetiques quand ces composants co-existent. C'est appele apres les reductions FP pour ne pas etre annule.

---

## Etat actuel

### Ce qui fonctionne

- **14 scanners paralleles**, 158 regles de detection (153 + 5 paranoid)
- **225 000+ IOCs** npm + 14 000+ PyPI
- Detection de campagnes : Shai-Hulud (v1/v2/v3), GlassWorm (433+ packages)
- Sandbox Docker avec simulation CI, canary tokens, monkey-patching preload, multi-run
- Moniteur zero-day : npm changes stream + PyPI RSS, alertes Discord temps reel
- Exports JSON, HTML, SARIF. Extension VS Code. GitHub Action Marketplace
- Diff entre versions, pre-commit hooks, mode paranoid
- Detection comportementale : lifecycle temporel, AST diff, anomalie publication, changement maintainer
- Desobfuscation statique : concat, charcode, base64, hex arrays, propagation de constantes
- Dataflow inter-module : graphe de dependances, propagation de teinte, 3-hop re-export
- Compound scoring : 7 regles zero-FP pour les co-occurrences malveillantes
- Pipeline ML : extraction 71 features, classifier XGBoost JS pur (stub, en attente de donnees)
- **2533 tests** (56 fichiers), 86% coverage

### Ce qui manque (honnetement)

**ML en shadow mode** : Le classifier XGBoost est implemente avec 71 features enrichies, mais le modele est un stub en attente de donnees suffisantes. Le pipeline Python est pret. L'analyse repose encore principalement sur des patterns statiques, des IOCs connus, et des heuristiques comportementales.

**Pas d'interception TLS** : Le sandbox capture le SNI mais ne dechiffre pas le contenu HTTPS.

**Desobfuscation limitee** : La desobfuscation resout les patterns courants, mais les obfuscateurs avances (javascript-obfuscator, JScrambler) utilisent des transformations de flux de controle que l'approche statique ne peut pas resoudre.

**Dependance aux APIs tierces** : Si DataDog, GitHub, ou OSV changent leurs APIs, le scraper casse.

**Support limite a npm et PyPI** : Pas de RubyGems, Maven, Go, ou autres ecosystemes.

**Pas de dashboard web** : MUAD'DIB est un outil CLI local uniquement.

---

## Liens

- **npm** : npmjs.com/package/muaddib-scanner
- **GitHub** : github.com/DNSZLSK/muad-dib
- **VS Code** : marketplace.visualstudio.com/items?itemName=dnszlsk.muaddib-vscode
- **Discord** : discord.gg/y8zxSmue

---

## Conclusion

MUAD'DIB n'est pas parfait. C'est un projet de formation, pas un produit enterprise. Mais il fonctionne pour ce qu'il est cense faire : detecter les menaces npm et PyPI connues, analyser les comportements suspects dans un sandbox, et prouver son efficacite avec des metriques de validation honnetes.

*"Fear is the mind-killer. I will face my fear."* - Dune, Frank Herbert
