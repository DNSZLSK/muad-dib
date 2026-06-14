# sink-coupling-fp — fixtures de gate pour le chantier FPR (Étape A → C)

Fixtures issues de l'adjudication aveugle du 2026-06-14 (`FPR-adjudication-2026-06-14.md`).
Elles encodent le **discriminant du rubric** : un signal d'install/exec/harvest n'est un TP que
s'il est **couplé à un sink** (exec de code distant / exfil vers un host anormal). Sans sink = FP.

Chaque paire fait feu sur **le même signal** ; seul le sink change. Le fix Étape C
(sink-coupling sur `credential_regex_harvest` + `lifecycle_script`/exec) doit faire chuter les
négatifs sous le seuil **sans** toucher aux positifs. Ces fixtures sont les gates.

## Négatifs — `tests/samples/sink-coupling-fp/` (signal fire, AUCUN sink → doit cesser d'escalader après C)
| Fixture | Modèle réel (FP confirmé) | Signaux émis (mesurés) | Pourquoi FP (discriminant) |
|---|---|---|---|
| `framework-bundle/` | react-markup, @sveltejs/kit | `credential_regex_harvest` [HIGH] | regex de redaction (keyword token/bearer) + `https.get` first-party (registry.npmjs.org) dans le même fichier `cjs/index.js` ; le credential ne **coule pas** vers l'appel. |
| `native-addon/` | @lordofdestiny/mynumber | `native_addon_install` [HIGH] + `lifecycle_script` | `binding.gyp` + sources C++ + install node-pre-gyp = build **local**, pas d'exfil. |
| `vendor-banner/` | opticore-asymmetric-cryption | `typosquat_lifecycle` [CRITICAL] + `dependency_typosquat` + `lifecycle_script` | dép suffix-squat (`secure-chalk`) + postinstall **banner cosmétique** ; aucun sink. Compound typosquat résiduel. |

## Positifs — `tests/samples/staged-loader/` (signal fire, sink RÉEL → doit rester flaggé après C)
| Fixture | Modèle réel (TP confirmé) | Signaux émis (mesurés) | Sink |
|---|---|---|---|
| `credential-harvest-exfil/` | chalk-pro (volet harvest) | `credential_regex_harvest` [HIGH] + `suspicious_domain` + `ioc_string_match` | le credential matché **coule** dans `https.request` → `jsonkeeper.com` (host anormal). |
| `postinstall-detached-loader/` | chalk-pro + richtext-editor-ui (reach) | `detached_process` + `silent_stealth_process` + `lifecycle_file_exec` + `dangerous_call_function` + `ioc_string_match` + `suspicious_domain` | postinstall → node détaché furtif → `axios.get(jsonkeeper)` → `new Function(require, ...)`. |

## Comportement attendu (spec des tests Étape C)
- **Aujourd'hui (pré-fix)** : les 3 négatifs ET les 2 positifs escaladent (suspect). C'est le bug : `credential_regex_harvest` sur `framework-bundle` (FP) est indiscernable de `credential-harvest-exfil` (TP).
- **Après Étape C (sink-coupling)** :
  - négatifs → **PAS de suspect** (signal présent mais aucun sink/dataflow vers host anormal).
  - positifs → **toujours suspect** (sink réel : remote-exec ou exfil vers `jsonkeeper`).
- Gate : `npm test` 0 fail ; FPR↓ sur les négatifs ; TPR inchangé sur les positifs.

## Mécanique détecteur (mesurée 2026-06-14, à exploiter en C)
- `credential_regex_harvest` (`ast.js` + `handle-post-walk.js:219`) = `hasCredentialRegex` (regex literal/`new RegExp` contenant `bearer|password|secret|token|credential|api.?key`) **ET** `hasNetworkCallInFile` (`fetch|https?.request|https?.get|dns.resolve`) **dans le même fichier**. → **pas de dataflow credential→sink, pas de réputation de host** : c'est le levier exact du fix.
- **`axios.*` n'est PAS reconnu** comme appel réseau (gap) → un harvester via axios échappe à `credential_regex_harvest` (rattrapé seulement par `ioc_string_match`/`suspicious_domain` si l'URL est un IOC connu).
- **`dist/`, `build/`, `out/`, `output/` sont exclus du scan** (`EXCLUDED_DIRS`, `utils.js:11`) ; `cjs/`, `lib/`, racine sont scannés. Asymétrie : un bundle malveillant en `dist/` passe sous le radar ; les libs livrant en `cjs/`/racine FP. (react-markup fire via `cjs/`.)
