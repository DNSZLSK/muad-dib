# Candidats fix — HEBDO 2026-07-16 (specs mesurables, review only)

Deux candidats issus de la review. **Ni l'un ni l'autre n'est implémenté** — specs pour décision + protocole de mesure. Contraintes projet : mesurer FPR AVANT, test positif ET négatif, seuil global, pas de whitelist, ΔFPR ≤ 0.

---

## FIX 1 — `reverse_shell` (AST) sur-tire → FP score 100 sur CLI légitimes

### Problème (preuve)
`src/scanner/ast.js:199` définit `hasJsReverseShell` par **co-occurrence de substrings au niveau fichier**, sans lien entre eux :

```js
hasJsReverseShell: /\bnet\.Socket\b/.test(content) &&
  /\.connect\s*\(/.test(content) &&
  /\.pipe\b/.test(content) &&
  (/\bspawn\b/.test(content) || /\bstdin\b/.test(content) || /\bstdout\b/.test(content)),
```

`handle-post-walk.js:140-148` émet alors `reverse_shell` CRITICAL (message : « net.Socket + connect() + pipe to shell process stdin/stdout »). Or rien n'exige que le socket soit **réellement câblé au stdio d'un shell**. Tout CLI qui bundle une lib réseau (undici/proxy-agent/net) contient `net.Socket` + `.connect(` + `.pipe` (streams) + `stdout` (I/O CLI) → 4 substrings présents → score 100 CRITICAL.

**FP mesurés (review 2026-07-16, tous npm LIVE, lus manuellement) :**
- `@coze/cli` (score 100) — Coze platform CLI ; `spawn/exec` réels = `powershell -Command`, `npm config get registry`
- `@vm0/cli` (score 100) — `net.connect` = strings d'erreur d'une lib d'interception réseau ; `execFile("/usr/bin/sw_vers")`
- `@fetch-client/cli` (score 100) — **0 `child_process`** ; `.connect` dans code proxy-agent bundlé

Même famille que `suspicious_dataflow` (cf `project_rule_audit_map` : #1 sur-pondéré ~99 % FP).

### Vraie forme d'un reverse shell JS
Le stream d'un socket est **câblé au stdio d'un process shell** : `socket.pipe(child.stdin)` / `child.stdout.pipe(socket)` / `spawn('/bin/sh', {stdio:[socket,socket,socket]})`. Les deux contraintes manquantes : (a) un **spawn de shell réel** (`sh`/`bash`/`cmd`/`powershell`/`/bin/*sh`), (b) le **pipe qui relie socket ↔ stdio du child**, pas la co-présence.

### Changement proposé (`ast.js:199` + option AST)
- **Minimum viable** : exiger la co-présence d'un **spawn de shell** — `spawn`/`exec*` avec un argument binaire shell (`/\b(spawn|exec\w*)\s*\([^)]*['"\`](\/bin\/)?(ba)?sh|cmd(\.exe)?|powershell/`). Retirer le satisfieur `stdin`/`stdout` **seul** (ubiquitaire).
- **Précis (recommandé)** : dans `handle-call-expression.js`, détecter le câblage réel (pipe dont la cible est un `child.stdin`/`stdout`, ou `stdio:[socket,...]`) et poser un flag dédié `hasJsReverseShellWired` ; `reverse_shell` ne tire que sur ce flag.
- **Downweight bundle** : appliquer `src/shared/bundle-detect.js` — dans un `.min.js`/dist bundlé, dégrader CRITICAL→HIGH (comme `self_destruct_eval` fait déjà via `isDistFile`), le vrai revshell n'est jamais dans un bundle vendor.

### Protocole de mesure (gate : ΔFPR(reverse_shell) < 0 ET ΔTPR(GT) = 0)
1. **FPR** : re-scan des 3 FP confirmés → `reverse_shell` ne doit plus tirer (score < 20). + scan de N CLI populaires benins bundlant undici/axios/proxy-agent (depuis le set FPR benign 545) → attendu `reverse_shell` = 0.
2. **TPR** : `tests/samples/shell` + tout GT à `reverse_shell` + le fixture historique `npx-whoami-demo` (cité `shell.js:65` comme miss réel) → doivent toujours scorer ≥ 20. **Créer un fixture positif** : socket câblé à `spawn('/bin/sh')` → doit tirer. **Fixture négatif** : CLI avec net.Socket+pipe+stdout SANS spawn shell → ne doit PAS tirer.
3. `muaddib evaluate` avant/après ; comparer FPR benign + TPR@20 GT.

### Rollback
Revert de la condition `ast.js:199` (+ flag AST si ajouté).

---

## FIX 2 — Persistance cron/schtasks via `execSync('… | crontab -')` non catégorisée

### Problème (preuve)
`crontab_systemd_write` (`handle-call-expression.js:1978`) ne tire QUE sur `writeFileSync`/`writeFile`/`appendFileSync` vers un **chemin** cron (`/etc/cron`, `crontab`, `/var/spool/cron`). Or phantom-syncd installe la persistance par **exécution de commande** :

```js
c.execSync('(crontab -l 2>/dev/null | grep -v syncd; echo "0 */12 * * * /usr/bin/node '+s+' >/dev/null 2>&1") | crontab -');
// et Windows :
c.execSync('schtasks /create /tn "WinNodeSync" /tr "node '+s+'" /sc hourly /mo 12 /f');
```

Ni le `| crontab -` (Linux) ni le `schtasks /create` (Windows) ne sont détectés → la persistance n'est pas surfacée. **Ce n'est PAS un miss** (les packages scorent 100 via `detached_credential_exfil` etc.), mais un trou d'observabilité : le mécanisme de persistance — signal fort et distinctif — reste invisible dans l'alerte.

### Changement proposé (`shell.js` patterns et/ou `handle-call-expression.js`)
Détecter la persistance par exécution de commande sur les args de `exec`/`execSync`/`spawn` :
- `crontab\s+-` (surtout piped `\|\s*crontab\s+-`) — écriture de crontab
- `schtasks\s+/create` — tâche planifiée Windows
- `systemctl\s+(enable|--user\s+enable)`, `launchctl\s+load`, write vers `/etc/systemd/system` ou `~/.config/systemd/user`
- Bonus : `crontab\s+-l[^|]*\|\s*grep\s+-v` (self-hiding : liste puis se retire du grep) = suspect en soi.

Émettre `crontab_systemd_write` (ou nouveau `persistence_via_exec`) CRITICAL.

**Note gap connexe (changement séparé, PAS ce fix)** : le payload stable `keypairs.dat` (stage-2, identique sur 9+ packages, 4 hashes distincts) n'est pas hashable — `hash.js:52` scanne `extensions:['.js']` uniquement + `node_modules/` uniquement. Étendre `extensions` aux fixtures binaires (`.dat`/`.bin`, borné en taille) rendrait les payloads stagés hashables. (Les 7 hashes `index.js` seedés ce jour couvrent les renames purs ; le `.dat` couvrirait les repackagings.)

### Protocole de mesure (gate : nouveau TPR ET ΔFPR ≈ 0)
1. **TPR** : scan des samples phantom-syncd → `crontab_systemd_write`/`persistence_via_exec` doit maintenant tirer sur `index.js`. **Fixture positif** : `execSync('... | crontab -')` + `schtasks /create`. **Fixture négatif** : `execSync('crontab -l')` (lecture seule) et un script de build citant « cron » en commentaire → ne doivent PAS tirer.
2. **FPR** : scan du corpus benign (545) + random ; `\| crontab -` / `schtasks /create` en package benin est rare → attendu ≈ 0. Documenter tout hit.
3. Gate : ΔFPR < ε ET TPR sur les fixtures de persistance.

### Rollback
Retrait du/des pattern(s) ajouté(s).

---

## Priorité suggérée
FIX 1 (reverse_shell) d'abord — c'est un **générateur de FP score-100** actif (impact FPR direct). FIX 2 est de l'observabilité (pas de miss). Les deux passent par le protocole de mesure avant tout merge.
