# MUAD'DIB — Audit des Faux Positifs (FPR)

**Version analysée :** v2.2.28 (metrics/v2.2.28.json) + baseline v2.2.10
**Date de l'audit :** 2026-02-24
**Dataset :** 529 packages npm bénins (527 scannés, 2 skipped)
**Seuil FP :** score > 20

| Version | FP | FPR | TPR | ADR |
|---|---|---|---|---|
| v2.2.10 (baseline) | 69/527 | **13.1%** | 100% (4/4 old GT) | — |
| v2.2.28 (current) | 86/527 | **16.3%** | 91.8% (45/49) | 100% (78/78) |
| Delta | **+17 FP** | **+3.2%** | — | — |

**Régression causée par les 8 nouvelles règles SANDWORM_MODE (AST-024 à AST-031).**

---

## 0. Impact des nouvelles règles (v2.2.28 vs v2.2.10)

| Nouvelle règle | Packages FP | Threats | Sévérité | Commentaire |
|---|---|---|---|---|
| `module_compile_dynamic` (AST-025) | **17** | **54** | CRITICAL | **Pire offender.** Template engines, bundlers, et compilateurs utilisent `Module._compile()` légitimement |
| `write_execute_delete` (AST-026) | 7 | 10 | HIGH | Packages qui font build + cleanup |
| `env_harvesting_dynamic` (AST-029) | 7 | 8 | HIGH | `Object.entries(process.env)` dans des config loaders |
| `zlib_inflate_eval` (AST-024) | 6 | 7 | CRITICAL | zlib + base64 + eval dans du code bundlé |
| `dns_chunk_exfiltration` (AST-030) | 3 | 3 | HIGH | DNS + base64 dans du code réseau légitime |
| `mcp_config_injection` (AST-027) | 0 | 0 | CRITICAL | OK — aucun FP |
| `git_hooks_injection` (AST-028) | 0 | 0 | HIGH | OK — aucun FP |
| `llm_api_key_harvesting` (AST-031) | 0 | 0 | MEDIUM | OK — aucun FP |

### 18 nouveaux packages flaggés (absents de v2.2.10)

| Package | Cause principale |
|---|---|
| mathjs | module_compile_dynamic (×20+ fichiers math node) |
| pnpm | zlib_inflate_eval + write_execute_delete + dns_chunk |
| @babel/core | module_compile_dynamic (compiler) |
| lerna | write_execute_delete (monorepo build/cleanup) |
| pdfkit | zlib_inflate_eval (font compression) |
| exceljs | crypto_decipher (Excel encryption) |
| pug | module_compile_dynamic (template compiler) |
| art-template | module_compile_dynamic (template compiler) |
| nunjucks | template compilation patterns |
| @angular/core | module_compile_dynamic (AOT compiler) |
| million | template compiler |
| mini-css-extract-plugin | module_compile_dynamic |
| postcss-loader | module_compile_dynamic |
| prettier | code formatting patterns |
| stylelint | linting patterns |
| @typescript-eslint/eslint-plugin | AST manipulation |
| blitz | framework patterns |
| node-forge | crypto patterns |

### 1 package unflag (présent v2.2.10, absent v2.2.28)

- `recoil` : score légèrement réduit (28 → ≤20) grâce à l'absence de hit des nouvelles règles

### Recommandations urgentes pour les nouvelles règles

1. **`module_compile_dynamic` :** Exiger que l'argument ne soit PAS une variable locale initialisée à un string literal (pattern compilateur légitime). Ou: count-based downgrade >3 → LOW
2. **`write_execute_delete` :** Exiger que write+exec+delete ciblent le MÊME fichier temporaire, pas juste tmpdir en général
3. **`env_harvesting_dynamic` :** Whitelist si le fichier s'appelle `config.*`, `env.*`, ou si le package est un framework de config (dotenv, etc.)
4. **`zlib_inflate_eval` :** Vérifier que l'eval est DYNAMIQUE (pas un polyfill) et que le zlib inflate cible du contenu runtime, pas des assets statiques (fonts, images)

---

## 1. Vue d'ensemble (baseline v2.2.10)

Les sections suivantes analysent la baseline v2.2.10 (69 FP) pour les causes racines profondes, indépendamment des nouvelles règles.

| Métrique | Valeur |
|---|---|
| Packages scannés | 527 |
| Faux positifs | 69 |
| FPR global | 13.1% |
| Menaces totales (FP) | 1232 |
| Score médian des FP | 35 |
| FP avec score 21-25 (marginaux) | 9 |
| FP avec score ≥ 100 | 7 |

### Distribution des scores

| Plage | Nombre |
|---|---|
| 21-30 | 18 packages |
| 31-40 | 22 packages |
| 41-50 | 7 packages |
| 51-60 | 8 packages |
| 61-70 | 6 packages |
| 71-80 | 1 package |
| 91-100 | 7 packages |

### Sensibilité au seuil

| Seuil | FP | FPR |
|---|---|---|
| >20 (actuel) | 69 | 13.1% |
| >25 | 60 | 11.4% |
| >30 | 51 | 9.7% |
| >35 | 40 | 7.6% |
| >40 | 29 | 5.5% |
| >50 | 22 | 4.2% |

---

## 2. FP par sévérité

| Sévérité | Occurrences | % du total |
|---|---|---|
| HIGH | 478 | 38.8% |
| MEDIUM | 327 | 26.5% |
| LOW | 321 | 26.1% |
| CRITICAL | 106 | 8.6% |

### Menaces CRITICAL dans des packages bénins (problème majeur)

| Règle | Occurrences |
|---|---|
| suspicious_dataflow | 29 |
| require_cache_poison | 21 |
| staged_payload | 20 |
| obfuscation_detected | 14 |
| binary_dropper | 5 |
| known_malicious_package | 5 |
| reverse_shell | 4 |
| env_proxy_intercept | 3 |
| ai_agent_abuse | 2 |
| prototype_hook | 1 |
| dynamic_require_exec | 1 |
| credential_tampering | 1 |

---

## 3. FP par règle

### Classement par nombre de packages affectés

| Règle | Packages affectés | Hits totaux | Points pondérés |
|---|---|---|---|
| suspicious_dataflow | 37 | 102 | 1140 |
| env_access | 37 | 220 | 1367 |
| dynamic_require | 33 | 208 | 1054 |
| dangerous_call_function | 27 | 122 | 176 |
| typosquat_detected | 23 | 32 | 320 |
| require_cache_poison | 20 | 33 | 537 |
| obfuscation_detected | 18 | 69 | 423 |
| lifecycle_script | 18 | 20 | 60 |
| dynamic_import | 17 | 83 | 830 |
| dangerous_call_eval | 15 | 40 | 292 |
| env_charcode_reconstruction | 15 | 19 | 190 |
| high_entropy_string | 13 | 58 | 258 |
| staged_payload | 11 | 20 | 500 |
| prototype_hook | 8 | 145 | 674 |
| staged_binary_payload | 5 | 6 | 60 |
| known_malicious_package | 5 | 5 | 125 |
| sandbox_evasion | 4 | 4 | 40 |
| detached_process | 4 | 7 | 70 |
| reverse_shell | 3 | 4 | 100 |

### Classement par impact sur le score (« threshold pushers »)

Si on supprimait une seule règle, combien de packages passeraient sous le seuil de 20 ?

| Règle | Packages qui seraient unflag |
|---|---|
| suspicious_dataflow | 7 |
| typosquat_detected | 6 |
| require_cache_poison | 5 |
| dynamic_require | 4 |
| obfuscation_detected | 4 |
| dynamic_import | 3 |
| staged_payload | 3 |
| env_access | 3 |
| lifecycle_script | 2 |
| known_malicious_package | 2 |

---

## 4. FP par catégorie de package

| Catégorie | FP/Total | FPR |
|---|---|---|
| **Frameworks web** | 9/25 | **36%** |
| **Monorepo tools** | 4/12 | **33%** |
| **Testing** | 7/25 | **28%** |
| **DevOps/CI** | 5/18 | **28%** |
| **Email** | 2/8 | **25%** |
| **PDF/docs** | 2/8 | **25%** |
| **Templating** | 2/9 | **22%** |
| **Build tools** | 7/35 | **20%** |
| **Date/time** | 2/10 | **20%** |
| **Queue/workers** | 2/10 | **20%** |
| **Linters/formatters** | 3/18 | **17%** |
| **Wasm/native** | 2/12 | **17%** |
| Validation/schema | 2/15 | 13% |
| Database | 3/25 | 12% |
| Codegen/AST | 2/18 | 11% |
| Miscellaneous | 4/39 | 10% |
| State management | 1/10 | 10% |
| Image/media | 1/10 | 10% |
| Markdown/text | 1/10 | 10% |
| Config/env | 1/10 | 10% |
| Bibliothèques UI | 2/25 | 8% |
| HTTP/networking | 2/25 | 8% |
| CLI tools | 2/30 | 7% |
| Logging/monitoring | 1/14 | 7% |

**Observation :** Les frameworks web (Next.js, Gatsby, Vite) et les outils monorepo (npm, yarn, nx) sont les plus touchés. Ces packages sont gros, ont du code bundlé dans `dist/`, et utilisent légitimement des patterns détectés (dynamic require, process.env, require.cache).

---

## 5. Analyse des chemins de fichiers

| Chemin | Menaces | % du total |
|---|---|---|
| `dist/` | 537 | 43.6% |
| `lib/` | 327 | 26.5% |
| autre | 214 | 17.4% |
| `src/` | 77 | 6.3% |
| `package.json` | 58 | 4.7% |
| `test/` | 11 | 0.9% |
| `node_modules/` | 8 | 0.6% |

**Constat majeur :** 43.6% des menaces FP proviennent de fichiers `dist/` — du code bundlé/minifié qui contient des patterns légitimes compressés ensemble.

### Impact simulé de l'exclusion `dist/`

Si on excluait les fichiers `dist/` et `build/` du scoring :

- 17 packages seraient unflag (69 → 52)
- FPR passerait de 13.1% à **9.9%**
- Packages unflag : next, nuxt, htmx.org, vite, rollup, vitest, storybook, @storybook/react, oxlint, @changesets/cli, @napi-rs/cli, netlify-cli, @vue/compiler-sfc, class-validator, handlebars, recoil, jimp

---

## 6. Analyse détaillée des top 10 règles

### R1 — `suspicious_dataflow` (37 packages, 1140 pts)

**Cause racine :** Le scanner dataflow détecte `os.networkInterfaces()`, `os.hostname()`, `os.arch()`, `process.env[dynamic]` comme « lecture de credentials » et `dns.lookup()`, `http.request()`, `fetch()` comme « envoi réseau ». La co-occurrence de ces deux patterns dans le même fichier déclenche l'alerte.

**Pourquoi c'est un FP :**
- `os.networkInterfaces()` + `dns.lookup()` est le pattern standard de **fastify** pour le bind réseau
- `process.env[dynamic]` + `fetch()` est universel dans tout framework web (config + HTTP client)
- Les fichiers bundlés (`dist/`) combinent des modules distincts dans le même fichier, créant des co-occurrences artificielles

**Exemples concrets :**
| Package | Fichier | Pattern |
|---|---|---|
| fastify | lib/server.js | `os.networkInterfaces()` + `dns.lookup()` (bind réseau) |
| next | dist/compiled/@vercel/nft/index.js | `process.env[dynamic]` + `get()` (config + HTTP bundled) |
| next | dist/compiled/@vercel/og/index.edge.js | `FIGMA_PERSONAL_ACCESS_TOKEN` + `get()` (env var officielle Vercel) |
| typescript | lib/typescript.js | `os.platform()` + `http.request()` (update check) |
| dotenv | lib/main.js | `process.env` access + write (c'est littéralement sa fonction) |

**Recommandation :**
1. **Taux de sources vs sinks :** Si ratio sources/sinks > 5 (ex : 50 `process.env` reads, 3 `http.get`), c'est un framework, pas du malware → downgrade à LOW
2. **Whitelist `os.networkInterfaces` + `dns.lookup`** : Ce pattern est du bind réseau, jamais de l'exfiltration
3. **Downgrade dans `dist/` :** Les menaces dataflow dans `dist/*.js` devraient être LOW (co-occurrence artificielle du bundling)

---

### R2 — `env_access` (37 packages, 1367 pts)

**Cause racine :** Détecte tout accès à `process.env.SENSITIVE_NAME` (HIGH) et `process.env[variable]` (MEDIUM). Les env vars « sensibles » incluent des patterns comme `*TOKEN*`, `*KEY*`, `*SECRET*`, `*AUTH*`.

**Pourquoi c'est un FP :**
- `process.env.__NEXT_EXPERIMENTAL_AUTH_INTERRUPTS` trigger sur `AUTH` → c'est un flag Next.js, pas un secret
- `process.env[dynamic]` est le pattern universel de configuration (dotenv, config loaders)
- Les frameworks web accèdent légitimement à `PORT`, `HOST`, `NODE_ENV`, `DEBUG` qui ne sont pas des secrets

**Exemples concrets :**
| Package | Fichier | Env var |
|---|---|---|
| next | dist/client/components/forbidden.js | `__NEXT_EXPERIMENTAL_AUTH_INTERRUPTS` (flag interne) |
| next | dist/compiled/@vercel/og/index.edge.js | `FIGMA_PERSONAL_ACCESS_TOKEN` (env officielle Vercel) |
| next | dist/compiled/next-server/server.runtime.prod.js | `DOTENV_KEY` (dotenv bootstrap) |
| pm2 | lib/ProcessContainerFork.js | `PM2_TOKEN`, `PM2_SECRET` (config PM2) |
| nx | bin/nx.js | `NX_CLI_SET` (flag interne) |

**Recommandation :**
1. **Whitelist des patterns framework :** `__NEXT_*`, `PM2_*`, `NX_*`, `VITE_*`, `REACT_APP_*`, `GATSBY_*` ne sont pas des secrets
2. **Seuil de volume :** >10 accès `process.env` dans le même package → c'est un framework de config, pas du malware → downgrade HIGH→MEDIUM, MEDIUM→LOW
3. **Exclure `process.env[dynamic]` des fichiers de config** : quand le fichier s'appelle `config.js`, `env.js`, `.env.js` etc.

---

### R3 — `dynamic_require` (33 packages, 1054 pts)

**Cause racine :** Détecte `require(variable)` et `require(expression)`. Les plugins systèmes, les module loaders, et les bundlers utilisent tous du dynamic require.

**Pourquoi c'est un FP :**
- webpack/rollup/vite sont des bundlers — leur fonction est de charger dynamiquement des modules
- Plugin loaders (fastify, strapi, eslint) chargent des plugins par nom dynamique
- Le count-based downgrade (>10 → LOW) existe déjà dans `FP_COUNT_THRESHOLDS`

**Exemples concrets :**
| Package | Fichier | Pattern |
|---|---|---|
| webpack | lib/webpack.js | `require(dependency)` — c'est un bundler |
| strapi | lib/core/loaders/plugins.js | `require(pluginPath)` — plugin loader |
| typescript | lib/typescript.js | `require(moduleName)` — compiler module resolution |
| gatsby | dist/utils/start-server.js | `require(configPath)` — config loading |

**Recommandation :**
1. Le downgrade >10 fonctionne bien mais seulement pour les packages avec 11+ occurrences. **Baisser le seuil à 5** pour couvrir plus de cas
2. **Downgrade si le fichier s'appelle `loader.js`, `plugin*.js`, `config*.js`** — pattern de plugin loading

---

### R4 — `dangerous_call_function` (27 packages, 176 pts)

**Cause racine :** Détecte `new Function()` et `Function()`. Deux patterns légitimes majeurs :
1. `Function('return this')()` — le pattern standard de détection de `globalThis` (polyfill)
2. Template engines et code generators

**Pourquoi c'est un FP :**
- La majorité (LOW severity) sont des `Function('return this')()` polyfills
- Les template engines (handlebars, marko, @vue/compiler-sfc) génèrent du code via `Function()`
- Le downgrade >5 → LOW existe déjà

**Exemples concrets :**
| Package | Fichier | Pattern |
|---|---|---|
| next | dist/build/polyfills/polyfill-nomodule.js | `Function('return this')()` (globalThis polyfill) |
| handlebars | dist/cjs/handlebars/compiler/javascript-compiler.js | `Function(code)` (template compilation) |
| @vue/compiler-sfc | dist/compiler-sfc.cjs.js | `new Function(code)` (SFC compilation) |
| kue | lib/http/jade/runtime.js | `Function(code)` (template rendering) |

**Recommandation :**
1. **Détecter et exclure le pattern `Function('return this')()`** — c'est un polyfill documenté, jamais malveillant. Cela éliminerait ~50% des occurrences
2. **Template engine heuristic :** Si le fichier contient `compile`, `template`, `render` dans son chemin → downgrade à LOW

---

### R5 — `typosquat_detected` (23 packages, 320 pts)

**Cause racine :** La distance de Levenshtein entre les noms de dépendances et les packages populaires est trop sensible. Des packages totalement légitimes et populaires sont flaggés.

**Pourquoi c'est un FP :**
- `conf` flaggé comme typosquat de `config` — conf est un package populaire (2.7M downloads/semaine)
- `defu` flaggé comme typosquat de `debug` — defu est de l'écosystème UnJS (14.6M downloads)
- `cors` flaggé comme typosquat de `colors` — cors est un middleware Express standard (34M downloads)
- `ohash` flaggé comme typosquat de `lodash` — ohash est de l'écosystème UnJS (11.9M downloads)
- `meant` flaggé comme typosquat de `react` — meant est un package npm officiel

**Exemples :**
| Dépendance flaggée | Ressemble à | Downloads/semaine | Verdict |
|---|---|---|---|
| conf | config | 2,731,472 | FP — package légitime |
| defu | debug | 14,618,171 | FP — écosystème UnJS |
| cors | colors | 34,507,285 | FP — middleware Express |
| ohash | lodash | 11,938,024 | FP — écosystème UnJS |
| meant | react | 524,083 | FP — package npm officiel |
| whelk | chalk | 30,054 | FP — package légitime |
| obug | debug | 10,130,738 | FP — debug tool |
| mkdist | mkdirp | 200,842 | FP — UnJS build tool |

**Recommandation :**
1. **Seuil de downloads :** Si le package flaggé a > 100K downloads/semaine, c'est légitime → supprimer l'alerte
2. **Whitelist élargie :** Ajouter `conf`, `defu`, `cors`, `ohash`, `meant`, `whelk`, `obug`, `mkdist`, `marko`, `tracer`, `bluebird` à la whitelist typosquat
3. **Seuil d'âge :** Si le package existe depuis > 3 ans (>1095 jours) avec > 50K downloads → probablement légitime

---

### R6 — `require_cache_poison` (20 packages, 537 pts)

**Cause racine :** Détecte tout accès à `require.cache`. Les plugin loaders, hot-reload systems, et test frameworks utilisent `require.cache` légitimement pour l'invalidation de modules.

**Pourquoi c'est un FP :**
- `fastify` utilise `require.cache` pour le plugin system
- `webpack` et `mocha` gèrent le cache de modules pour le hot-reload
- Le downgrade >3 → LOW existe mais le seuil est trop bas

**Exemples :**
| Package | Fichier | Raison légitime |
|---|---|---|
| fastify | lib/plugin-utils.js | Plugin registration system |
| webpack | lib/webpack.js | Module hot-reload |
| mocha | lib/mocha.js | Test module reloading |
| nx | packages/nx/src/utils/register.js | Module cache invalidation |
| vitest | dist/chunks/cli-api.*.js | Test isolation |

**Recommandation :**
1. **Baisser le seuil** de 3 à 1 : même 2 accès à `require.cache` est souvent légitime
2. **Distinguer read vs write :** `require.cache[key]` (lecture/delete pour reload) est bénin ; `require.cache[key] = maliciousModule` (écriture) est malveillant. Seule l'écriture devrait être CRITICAL
3. **Downgrade systématique dans les bundlers/test frameworks**

---

### R7 — `obfuscation_detected` (18 packages, 423 pts)

**Cause racine :** Le scanner d'obfuscation détecte `long_single_lines` + `unicode_escapes` dans du code minifié/bundlé. Le code minifié est structurellement similaire au code obfusqué.

**Pourquoi c'est un FP :**
- Tout fichier `dist/*.min.js` est minifié = longues lignes + pas de whitespace
- Les fichiers `bundle.js` de webpack ont des unicode escapes pour les strings internationales
- Le downgrade >3 → LOW existe déjà, et le downgrade dans `dist/build/*.bundle.js` → LOW aussi

**Exemples :**
| Package | Fichier | Signaux |
|---|---|---|
| next | dist/build/polyfills/polyfill-nomodule.js | long_single_lines, unicode_escapes |
| svelte | compiler/index.js | long_single_lines, unicode_escapes |
| zod | lib/types.js | long_single_lines |
| typescript | lib/typescript.js | long_single_lines |

**Recommandation :**
1. **Étendre le downgrade `dist/build/` :** Actuellement limité à `dist/build/*.bundle.js`. Étendre à tout `dist/**/*.js` et `build/**/*.js`
2. **Score minimum pour l'obfuscation :** Exiger un score d'obfuscation > 60 au lieu de > 40 pour MEDIUM+ (les minifiers produisent ~45)
3. **Vérifier la présence de source maps :** Si `.map` file existe à côté → c'est du code minifié, pas obfusqué

---

### R8 — `prototype_hook` (8 packages, 674 pts — 145 hits)

**Cause racine :** Détecte `globalThis.fetch` override, `WebSocket.prototype.*` override. Les frameworks web (Next.js) et les test mocking libraries (MSW) overrident `fetch` légitimement.

**Pourquoi c'est un FP :**
- **Next.js** override `globalThis.fetch` pour le caching et le data revalidation (8 fichiers runtime)
- **MSW** (Mock Service Worker) intercepte `fetch` pour le mocking dans les tests
- **undici** est le HTTP client Node.js officiel, il extend les prototypes HTTP

**Exemples :**
| Package | Fichier | Pattern |
|---|---|---|
| next (×8 fichiers) | dist/compiled/next-server/app-route*.js | `globalThis.fetch` override (Next.js fetch caching) |
| next | dist/compiled/ws/index.js | `WebSocket.prototype.addEventListener` (WS library) |
| msw | dist/core/index.js | `globalThis.fetch` override (test mocking) |
| vitest | dist/chunks/cli-api.*.js | `globalThis.fetch` override (test mocking) |
| undici | lib/handler/redirect-handler.js | HTTP prototype extensions |
| superagent | lib/node/agent.js | `Request.prototype` (HTTP agent) |

**Recommandation :**
1. **Whitelist `globalThis.fetch` pour les frameworks connus :** Si le package est `next`, `nuxt`, `remix`, `msw`, `vitest` → downgrade fetch override à LOW
2. **Heuristique de volume :** >5 prototype hooks dans le même package → c'est un framework, pas du malware → downgrade tout à LOW
3. **Distinguer `globalThis.fetch` (interception) de `http.IncomingMessage.prototype` (core hijacking)**

---

### R9 — `known_malicious_package` (5 packages, 125 pts)

**Cause racine :** La base IOC contient des packages qui ont eu des versions malveillantes mais dont les versions propres sont encore utilisées. Les dépendances sont matchées sans vérification de version.

**Exemples :**
| Package parent | Dépendance flaggée | Source IOC | Problème |
|---|---|---|---|
| webpack | es5-ext@^0.10.53 | socket-dev | Version range inclut des versions propres |
| sass-loader | bootstrap-sass@^3.4.1 | npm-removed | Anciennes versions propres |
| eslint | eslint-config-eslint@file:packages/eslint-config-eslint | snyk-known | Référence monorepo `file:` |
| vercel | @vercel-internals/constants@1.0.4 | IOC | Package interne Vercel |
| moment | typescript3@npm:typescript@^3.1.6 | IOC | Alias npm, pas un vrai nom de package |

**Recommandation :**
1. **Version-aware matching :** Utiliser le format `versioned{}` de `iocs-compact.json` pour vérifier si la version spécifique est dans la plage malveillante
2. **Ignorer les dépendances `file:`** : Les références `file:packages/*` sont des monorepo, pas des packages npm
3. **Ignorer les alias `npm:`** : `typescript3@npm:typescript@^3.1.6` est un alias, pas le package `typescript3`

---

### R10 — `reverse_shell` (3 packages, 100 pts)

**Cause racine :** La détection combinée `net.Socket` + `.connect()` + `.pipe()` + (`spawn`|`stdin`|`stdout`) trigger sur du code réseau légitime bundlé dans `dist/`.

**Exemples :**
| Package | Fichier | Raison légitime |
|---|---|---|
| vite | dist/node/chunks/config.js | Code réseau HMR (Hot Module Replacement) bundlé |
| vitest | dist/chunks/cli-api.*.js | Child process management pour les tests |
| vercel | dist/commands/dev/index.js | Dev server avec proxy réseau |

**Recommandation :**
1. **Exiger la co-localisation :** `net.Socket().connect()` + `.pipe(process.stdin)` doit être dans la même **fonction** (pas le même fichier bundlé)
2. **Downgrade dans `dist/`** : Les fichiers bundlés combinent du code réseau et process management artificiellement
3. **Vérifier le pattern complet :** Un vrai reverse shell a `spawn('sh')` ou `spawn('cmd')` + pipe bidirectionnel. Un simple `socket.pipe(stream)` n'est pas un reverse shell

---

## 7. Les 69 packages flaggés

| # | Package | Score | Catégorie | Règles principales |
|---|---|---|---|---|
| 1 | next | 63 | Framework web | 18 règles (bundled dist/) |
| 2 | vite | 100 | Build tool | reverse_shell, sandbox_evasion, env_charcode (bundled) |
| 3 | vercel | 100 | DevOps | known_malicious, reverse_shell, sandbox_evasion (bundled) |
| 4 | yarn | 100 | Monorepo | lifecycle, binary_dropper, prototype_hook, env_charcode |
| 5 | npm | 100 | Monorepo | lifecycle, typosquat, dynamic_require |
| 6 | keystone | 100 | Framework web | obfuscation, high_entropy (CodeMirror bundled) |
| 7 | total.js | 100 | Framework web | 10+ règles (framework monolithique) |
| 8 | playwright | 100 | Testing | env_charcode, require_cache, obfuscation (Chromium tooling) |
| 9 | pm2 | 80 | DevOps | detached_process, sandbox_evasion (process manager) |
| 10 | eslint | 70 | Linter | known_malicious (es-config monorepo ref) |
| 11 | vitest | 68 | Testing | prototype_hook, reverse_shell (test mocking + bundled) |
| 12 | nx | 68 | Monorepo | require_cache, sensitive_string, obfuscation |
| 13 | gatsby | 62 | Framework web | lifecycle, typosquat, require_cache |
| 14 | @vue/compiler-sfc | 61 | Codegen | dangerous_call_eval (template compilation) |
| 15 | typescript | 58 | Codegen | env_charcode, obfuscation (compiler bundle) |
| 16 | xml2js | 58 | Misc | env_charcode, staged_payload |
| 17 | msw | 56 | Testing | prototype_hook, node_inline_exec |
| 18 | xlsx | 53 | PDF/docs | obfuscation, high_entropy (spreadsheet data) |
| 19 | undici | 53 | HTTP | prototype_hook, js_obfuscation |
| 20 | webpack | 53 | Build tool | known_malicious (es5-ext), dynamic_import |
| 21 | superagent | 53 | HTTP | prototype_hook (HTTP agent) |
| 22 | storybook | 49 | Testing | dangerous_call_function, obfuscation |
| 23 | svelte | 48 | UI lib | dynamic_import, obfuscation (compiler) |
| 24 | esbuild | 48 | Build tool | lifecycle, binary_dropper (Go binary) |
| 25 | @changesets/cli | 48 | Monorepo | detached_process, dynamic_require |
| 26 | kue | 55 | Queue | dangerous_call_eval (jade templates) |
| 27 | sails | 45 | Framework web | dynamic_require, typosquat |
| 28 | mailgun.js | 44 | Email | prototype_hook, env_charcode |
| 29 | jspdf | 42 | PDF | prototype_hook, obfuscation |
| 30 | iconv-lite | 40 | Misc | high_entropy (encoding tables) |
| 31 | jimp | 40 | Image | staged_binary_payload (image processing) |
| 32 | sass-loader | 38 | Build tool | known_malicious (bootstrap-sass) |
| 33 | netlify-cli | 38 | DevOps | lifecycle, typosquat |
| 34 | htmx.org | 37 | UI lib | dangerous_call_eval, staged_payload |
| 35 | bottleneck | 37 | Queue | dangerous_call_eval, typosquat |
| 36 | oclif | 36 | CLI | lifecycle, env_access |
| 37 | bluebird | 36 | Misc | dangerous_call_eval, typosquat |
| 38 | typeorm | 36 | Database | lifecycle, dynamic_require |
| 39 | @prisma/client | 36 | Database | dangerous_call_function, env_charcode |
| 40 | oxlint | 36 | Linter | dynamic_import, env_charcode |
| 41 | marko | 35 | Templating | require_cache, dangerous_call_eval |
| 42 | blessed | 35 | CLI | require_cache, dynamic_require |
| 43 | moleculer | 35 | Framework web | env_access, require_cache |
| 44 | strapi | 35 | Framework web | dynamic_require, require_cache |
| 45 | istanbul | 35 | Testing | dynamic_require, typosquat |
| 46 | moment | 35 | Date | known_malicious (typescript3 alias) |
| 47 | dotenv | 35 | Config | env_access, suspicious_dataflow |
| 48 | js-beautify | 35 | Markdown | dynamic_require, typosquat |
| 49 | node-pre-gyp | 35 | Wasm/native | dynamic_require, typosquat |
| 50 | @napi-rs/cli | 33 | Wasm/native | env_access, typosquat |
| 51 | puppeteer-core | 31 | Misc | lifecycle, env_access |
| 52 | knex | 30 | Database | dynamic_import, typosquat |
| 53 | np | 30 | DevOps | env_access |
| 54 | nuxt | 30 | Framework web | dynamic_import, typosquat |
| 55 | aws-sdk | 29 | Email | lifecycle, credential_tampering |
| 56 | eslint-plugin-import | 28 | Linter | env_access, suspicious_dataflow |
| 57 | release-it | 28 | DevOps | dynamic_import, env_access |
| 58 | recoil | 28 | State | env_access, suspicious_dataflow |
| 59 | @storybook/react | 26 | Testing | env_charcode, env_access |
| 60 | rollup | 26 | Build tool | lifecycle, dynamic_require |
| 61 | date-fns | 25 | Date | obfuscation (locale data) |
| 62 | zod | 25 | Validation | obfuscation (type schema) |
| 63 | mocha | 25 | Testing | dynamic_require, require_cache |
| 64 | class-validator | 25 | Validation | obfuscation |
| 65 | fastify | 25 | Framework web | require_cache, suspicious_dataflow |
| 66 | webpack-dev-server | 23 | Build tool | lifecycle, dynamic_require |
| 67 | unbuild | 23 | Build tool | lifecycle, typosquat |
| 68 | handlebars | 21 | Templating | dangerous_call_function (template) |
| 69 | tracer | 21 | Logging | dangerous_call_eval, typosquat |

---

## 8. FP marginaux (score 21-25) — Quick wins

Ces 9 packages sont juste au-dessus du seuil. Un léger tuning les ferait passer sous 20 :

| Package | Score | Règles | Fix possible |
|---|---|---|---|
| fastify | 25 | require_cache, suspicious_dataflow | Whitelist os.networkInterfaces+dns.lookup |
| mocha | 25 | dynamic_require, require_cache, obfuscation | Baisser seuil require_cache à 1 |
| zod | 25 | obfuscation | Seuil obfuscation à 60 |
| class-validator | 25 | obfuscation | Seuil obfuscation à 60 |
| date-fns | 25 | obfuscation | Seuil obfuscation à 60 |
| webpack-dev-server | 23 | lifecycle, dangerous_call_function | Exclure `prepare` lifecycle script |
| unbuild | 23 | lifecycle, typosquat | Whitelist defu/mkdist + exclure prepare |
| handlebars | 21 | dangerous_call_function, typosquat | Exclure Function() dans template compilers |
| tracer | 21 | dangerous_call_eval, typosquat | Whitelist tracer |

---

## 9. Recommandations de correction (prioritisées)

### Priorité 0 — URGENT : Réduire les FP des nouvelles règles (v2.2.28 → v2.2.10 baseline)

| # | Action | Packages impactés | FP supprimés | Risque TPR |
|---|---|---|---|---|
| P0.1 | **`module_compile_dynamic` : count-based downgrade** >3 → LOW (comme require_cache_poison). Les compilateurs (Babel, Vue, Pug) ont 5-20 fichiers avec `_compile()` | 17 | ~10 | Nul — malware n'a jamais 4+ fichiers avec _compile |
| P0.2 | **`module_compile_dynamic` : exclure si arg est variable locale initialisée à un littéral** (pattern `const code = 'string'; Module._compile(code)` est un compilateur) | 17 | ~5 | Nul — les malwares utilisent des args dynamiques |
| P0.3 | **`zlib_inflate_eval` : exiger que l'eval soit dynamique** (pas un polyfill `Function('return this')`) et que le zlib inflate ne soit pas dans un fichier d'assets (fonts, images) | 6 | ~4 | Faible — le pattern réel (flatmap-stream) a du zlib+eval dynamique |
| P0.4 | **`write_execute_delete` : exiger le même fichier tmpdir** : write(tmpFile) + require(tmpFile) + unlink(tmpFile) doit cibler le même chemin, pas juste la co-occurrence de tmpdir dans le contenu | 7 | ~5 | Faible — les vrais anti-forensics ciblent le même fichier |
| P0.5 | **`env_harvesting_dynamic` : exclure si le fichier s'appelle `config.*`, `env.*`, `runner.*`** ou si c'est un framework de config | 7 | ~4 | Faible — les config loaders énumèrent légitimement process.env |
| P0.6 | **`dns_chunk_exfiltration` : exiger que le DNS resolve soit dans un loop body** (pas juste hasDnsLoop flag set par n'importe quel dns call) | 3 | ~2 | Nul — l'exfil DNS requiert réellement une boucle |

### Priorité 1 — Impact élevé, risque faible (FPR −3 à −5%)

| # | Action | Packages impactés | FP supprimés | Risque TPR |
|---|---|---|---|---|
| P1.1 | **Downgrade dans `dist/`** : Toute menace file-level dans `dist/**/*.js` ou `build/**/*.js` → severity downgrade d'un cran (CRITICAL→HIGH, HIGH→MEDIUM, MEDIUM→LOW) | 17+ | ~17 | Faible — le code malveillant est rarement dans dist/ des packages npm |
| P1.2 | **Whitelist typosquat élargie** : Ajouter `conf`, `defu`, `cors`, `ohash`, `meant`, `whelk`, `obug`, `mkdist`, `marko`, `tracer`, `bluebird` | 10+ | ~6 | Nul — ces packages sont tous légitimes |
| P1.3 | **Seuil typosquat downloads** : Si le package flaggé a > 100K downloads/semaine → supprimer l'alerte | 20+ | ~10 | Très faible — un package à 100K dl/sem n'est pas du typosquatting |

### Priorité 2 — Impact moyen, risque faible (FPR −2 à −3%)

| # | Action | Packages impactés | FP supprimés | Risque TPR |
|---|---|---|---|---|
| P2.1 | **require_cache read vs write** : Distinguer `delete require.cache[key]` (bénin, reload) de `require.cache[key] = {...}` (malveillant, hijacking). Read/delete → MEDIUM, write → CRITICAL | 20 | ~5 | Nul — la lecture du cache n'est pas une attaque |
| P2.2 | **Seuil obfuscation ≥ 60** : Monter le seuil de détection d'obfuscation de 40 à 60 pour MEDIUM+ (minifiers produisent ~45) | 18 | ~4 | Faible — le vrai code obfusqué a un score > 70 |
| P2.3 | **Exclure `Function('return this')()`** : Pattern globalThis polyfill documenté → ne pas compter comme `dangerous_call_function` | 27 | ~3 | Nul — c'est un polyfill standard |

### Priorité 3 — Impact ciblé (FPR −1 à −2%)

| # | Action | Packages impactés | FP supprimés | Risque TPR |
|---|---|---|---|---|
| P3.1 | **Version-aware IOC matching** : Pour `known_malicious_package`, vérifier la version exacte dans `versioned{}` avant de flag. Ignorer les ref `file:` et alias `npm:` | 5 | ~3 | Nul — meilleure précision |
| P3.2 | **Whitelist `os.networkInterfaces` + `dns.lookup`** : Ce pattern est du bind réseau, pas de l'exfiltration | 5 | ~2 | Très faible — jamais vu en malware |
| P3.3 | **env_access : whitelist framework prefixes** : `__NEXT_*`, `VITE_*`, `GATSBY_*`, `REACT_APP_*` ne sont pas des secrets | 15 | ~2 | Nul — ce sont des variables de configuration publiques |
| P3.4 | **reverse_shell : exiger le même scope** : Demander que net.Socket+connect+pipe soient dans la même fonction, pas juste le même fichier | 3 | ~3 | Faible — les vrais reverse shells sont co-localisés |
| P3.5 | **Exclure `prepare` des lifecycle_script** : `prepare` est un lifecycle npm standard pour la build, pas un vecteur d'attaque | 18 | ~2 | Faible — `prepare` est rare en malware (preinstall/postinstall sont les vrais vecteurs) |

### Impact estimé cumulé

| Scénario | FP estimés | FPR |
|---|---|---|
| Actuel (v2.2.28) | 86 | 16.3% |
| P0 seul (fix nouvelles règles) | ~68 | ~12.9% |
| P0 + P1 (+ dist/typosquat) | ~44 | ~8.3% |
| P0 + P1 + P2 | ~32 | ~6.1% |
| P0 + P1 + P2 + P3 | ~20 | ~3.8% |

---

## 10. Risques et précautions

### Ne PAS faire

1. **Ne pas augmenter le seuil global au-dessus de 25** — cela masquerait des vrais positifs (beaucoup de malware a un score de 25-35)
2. **Ne pas exclure `dist/` complètement** — certains malwares se cachent dans des fichiers pré-bundlés (ex: event-stream avait son payload dans un fichier compilé)
3. **Ne pas supprimer les règles** — chaque règle détecte des vrais positifs dans la ground truth. Il faut affiner, pas supprimer

### Vérifications requises avant chaque changement

- Relancer `muaddib evaluate` après chaque modification
- Vérifier TPR ≥ 91% (45/49) — aucune régression autorisée
- Vérifier ADR = 100% (78/78) — aucune régression autorisée
- Test sur les packages marginaux (score 21-25) en priorité

---

## Annexe A — Méthodologie

- **Source des données :** `metrics/v2.2.10.json` (evaluation baseline 2026-02-21) + `metrics/v2.2.28.json` (evaluation current 2026-02-24)
- **Scoring :** Per-file max scoring (v2.2.11). `riskScore = min(100, max(file_scores) + package_level_score)`
- **Seuil FP :** score > 20 (BENIGN_THRESHOLD dans evaluate.js)
- **Poids de sévérité :** CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1
- **FP reductions existantes :** dynamic_require >10→LOW, dangerous_call_function >5→LOW, require_cache_poison >3→LOW, suspicious_dataflow >5→LOW, obfuscation_detected >3→LOW, framework prototype hooks HIGH→MEDIUM
- **Nouvelles règles v2.2.28 :** AST-024 (zlib_inflate_eval), AST-025 (module_compile_dynamic), AST-026 (write_execute_delete), AST-027 (mcp_config_injection), AST-028 (git_hooks_injection), AST-029 (env_harvesting_dynamic), AST-030 (dns_chunk_exfiltration), AST-031 (llm_api_key_harvesting)
