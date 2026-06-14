# FPR baseline par règle — Étape B (2026-06-14)

Baseline **honnête, par règle**, avant tout changement de code (le chiffre qui manquait). Mesure par
adjudication **aveugle** d'un échantillon stratifié, instrumentée par le rubric sink-coupling figé en
Étape A (`FPR-adjudication-2026-06-14.md`). Données : `audit-data/fpr-baseline-2026-06-14.json`.

## Méthode
- **Population** : suspects npm récents du `scan-ledger.jsonl` (≈500k lignes balayées → 9880 suspects npm) ayant un tarball local dans `archive/` (adjudicables sans refetch).
- **Échantillon stratifié** (≥50/cluster — [[feedback_no_cluster_extrapolation]]) sur les 2 règles que l'Étape C touchera :
  - `credential_regex_harvest` : **801** suspects distincts avec tarball → **54** échantillonnés (18/bande de score).
  - lifecycle-compounds (`lifecycle_dangerous_exec`/`_file_exec`/`typosquat_lifecycle`/`_dataflow`/`_hidden_payload`/`_newsletter_hijack`) : **403** distincts → **54** (≈13%).
  - Union = **105** packages distincts.
- **Adjudication aveugle** : extraction déterministe de l'évidence de sink sur les 105 (`evidence.js` : hosts + classification first-party/anormal, eval+fetch, detached+unref, credential-regex+réseau, IP brutes, binding.gyp, serveur local), puis **lecture manuelle de CHAQUE package à sink anormal** (paste-site / IP publique / detached+host externe / eval+host non-first-party) + spot-checks de FP à score 100. Verdict sur le code, **pas** sur les labels MUAD'DIB.

## Résultat
| | n | TP | FP | UNC | **FP rate** |
|---|---|---|---|---|---|
| **Global** | 105 | 2 | 102 | 1 | **97.1 %** |
| `credential_regex_harvest` | 54 | 2 | 51 | 1 | **94.4 %** |
| lifecycle-compounds | 54 | 1 | 53 | 0 | **98.1 %** |

Par bande de score :
| bande | credential FP | lifecycle FP |
|---|---|---|
| low (20-34) | **100 %** (0 TP / 18) | **100 %** (0 TP / 18) |
| mid (35-74) | **100 %** (0 TP / 18) | **100 %** (0 TP / 18) |
| high (≥75) | 83.3 % (2 TP / 18) | 94.4 % (1 TP / 18) |

C'est la **précision d'alerte par règle** = taux de FP parmi les suspects où la règle a tiré.

## Les seuls vrais positifs (2/105) — tous à score 100, tous avec un sink anormal
- **ecto-corsair-whisper-6f3b9@1.0.14** (credential) — `postinstall.js` : chasse de flag `HTB{...}`, **dump `aws secretsmanager`** multi-régions, exfil → `webhook.site/602a4c72…` + C2 IP `154.57.164.82/71`, via `execFileSync("/bin/sh","-c",…)`. Gated sur conteneur cible (`isAppWorker`).
- **chalk-plus-js@7.0.4** (credential+lifecycle) — nodemailer publié sous le nom « chalk », `postinstall: node lib/utils/index.js` → `spawn(smtp-connection/index.js, {detached, stdio:ignore}).unref()` → loader `jsonkeeper`. **Variante de la campagne chalk-pro/richtext.**
- UNCERTAIN : `@nuiisweety/baileys@0.1.13` — fork Baileys, preinstall = version-check bénin, newsletter = code stock ; `saweria.co` à vérifier vs upstream.

## Findings
1. **La précision d'alerte des 2 drivers est ~94-98 % FP.** Sur 105 suspects échantillonnés, 2 malwares. Corrobore les adjudications antérieures (~97-99 % FP) mais **par règle** et post-v2.11.85.
2. **Les bandes 20-74 = 0 TP sur 72 packages = 100 % FP.** Tous les TP sont à score 100 **avec un sink**. Le score *corrèle* (les TP empilent des compounds → score haut) mais le **discriminant causal est le sink, pas le score** : à score 100, FP et TP coexistent (cf. Étape A : 6 FP / 2 TP à 150). Le low/mid score = « signal sans sink ».
3. ⚠️ **Ne PAS relever le seuil à 75** : des malwares à bas score existent via d'AUTRES signaux (nolimit-x@48, campagnes sub-20 des security reviews). Monter le seuil créerait des faux-négatifs. Le fix correct = **précision par sink-coupling**, indépendante du score.

## Projection Étape C (à valider par le fix + backtest, pas une promesse)
Sink-coupling = n'escalader `credential_regex_harvest` / lifecycle-compounds que si un sink anormal est atteignable (exfil/host anormal/remote-exec/detached-qui-exfil). Sur cet échantillon : **garde les 2 TP** (webhook.site, jsonkeeper — sinks anormaux) et **supprime les ~102 FP** (hosts first-party/vendor/doc, build local, serveur local, bundle, daemon détaché local). Réduction projetée sur ces 2 clusters : **94-98 % → ≈0 % FP, 0 perte de TP en échantillon**. À confirmer par les fixtures `tests/samples/sink-coupling-fp/` + backtest archive même-jour.

## Caveats (honnêtes)
- **Précision d'alerte**, pas FPR population complète (dénominateur bénin = corpus absent, [[project_eval_corpus_absent]]).
- **npm only** (pypi hors scope, plafonné à 35).
- Échantillon 105 (≥50/cluster ✓ ; credential ≈7 % de 801, lifecycle ≈13 % de 403).
- Risque résiduel de faux-négatif : extraction déterministe + lecture de tous les candidats à sink + spot-checks ; un sink enfoui/obfusqué vers un host whitelisté à tort pourrait échapper (faible).
- 1 UNCERTAIN (fork Baileys).

## Reproductibilité
Scripts : `/tmp/fpr-adj/{build-sample,make-chunks,evidence,classify,compute-baseline}.js` ; rubric `/tmp/fpr-adj/RUBRIC.md` ; verdicts `audit-data/fpr-baseline-2026-06-14.json`. (Fan-out par sous-agents abandonné : limite de session de compte atteinte → pivot adjudication scriptée+manuelle, plus reproductible.)
