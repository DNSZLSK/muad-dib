# Segment A diagnosis — destination-aware taint FPs (2026-06-14)

Read-only diagnosis (Step 1 of the approved plan) of the 12 T1a packages driven by the three
taint types. Goal: establish the exact failure mode per package → drives the precise fix.

## The 12 (11 FP + 1 TP), by sink type

| Package | Taint type | **Sink** | In-file destination(s) | Verdict / gateable |
|---|---|---|---|---|
| **ecto-corsair-whisper** | intent | network | **webhook.site + ext-IP 154.57.164.x** | **TP — real exfil. STAYS (suspicious-domain + ext-IP veto)** |
| agent-systems | intent | network | generativelanguage.googleapis.com + api.anthropic.com | FP — GEMINI not in map + multi-provider strict-fail |
| @remnic/plugin-codex | intent + detached | network | localhost:4318 (otel collector) | FP — **localhost = local IPC** |
| proxypro-harness | intent | network **+ exec** | localhost + example.com | FP (network part); exec part = out of scope |
| @zcouncil/cli | cross_file | network | openai/anthropic/x.ai + own + localhost | FP — **no gate wired**; multi-provider |
| contextdevkit | cross_file | network | google-AI + analytics CDNs | FP — no gate wired; multi-host |
| amicus | cross_file | network | openrouter.ai/openai/anthropic/deepseek | FP — no gate wired; multi-provider |
| claude-rpc | detached | network | own *.workers.dev + claude.com + gist | FP — no gate wired; own + multi |
| @dfosco/storyboard | cross_file | network | tailwind/base-ui CDNs + localhost (doc URLs) | FP — no gate wired; not even creds |
| @riddledc/riddle-proof | detached | network | own riddledc.com + localhost + discord | FP — no gate wired; own + local |
| **@policysynth/agents** | intent | **exec_sink** | (eval/Function, openAiResponsesCleanup.js) | FP — **NOT destination-gateable** |
| **@steedos/objectql** | intent | **exec_sink** | (eval, lib/util/index.js) | FP — **NOT destination-gateable** |

## Findings that refine the plan

1. **2 of 11 FPs are `credential_read → exec_sink`** (`@policysynth/agents`, `@steedos/objectql`;
   `proxypro-harness` partially). A destination gate **cannot** fix these — the sink is eval, there
   is no host to judge. They are a *separate* driver: legit AI SDK that reads an API key and uses
   `eval`/`new Function`/dynamic-`require` in the same file. **Out of segment-A scope** → documented
   follow-up. Segment A therefore recovers **~9**, not 13.

2. **The per-env-var model (`isSDKPattern`) is too narrow for multi-provider files.** `agent-systems`
   reads `GEMINI_API_KEY` **and** `ANTHROPIC_API_KEY` and calls **both** googleapis + anthropic. The
   curated path is strict all-match for ONE env var's domains → fails when a file legitimately talks
   to several providers. The right model is **destination-benignness**: suppress iff EVERY in-scope
   network destination is *known-benign* (provider-allowlist ∪ package-own-domain ∪
   loopback/localhost/private-IP) and NONE is anomalous.

3. **`cross_file_dataflow` + `detached_credential_exfil` have no destination check at all** — the
   single highest-leverage gap (6 of the 9 FPs). Wiring the destination-benignness gate here is the
   core of segment A.

4. **Loopback/localhost/private-IP must be treated as local (benign), distinct from external public
   IPs.** `isSDKPattern` today rejects *all* raw IPs → mislabels `127.0.0.1`/`localhost:4318`
   (otel/dev IPC) as suspicious. Anti-evasion preserved: ecto's **external public** IPs
   (154.57.164.x) stay anomalous.

5. **AI-provider allowlist gap** in `SDK_ENV_DOMAIN_MAP`: missing `GEMINI_`→generativelanguage.googleapis.com,
   `OPENROUTER_`→openrouter.ai, `DEEPSEEK_`, `XAI_`/`X_AI_`→x.ai, azure-cognitive, bedrock. The map
   predates the 2025-26 provider explosion.

6. **Anti-evasion (the SPOF concern, addressed):** the allowlist is curated and never includes
   abuse-prone "legit" channels (telegram/discord webhooks, gist/raw.githubusercontent, paste sites).
   Unknown domains count as **anomalous** (not suppressed) → a C2 on a normal-looking domain still
   fires. The suspicious-domain + external-IP + paste vetoes are absolute. This is the same curated
   pattern as the existing `SDK_ENV_DOMAIN_MAP` / FP-caps, bounded by the broad backtest.

## Garde-fou check — ecto STAYS (verified)
`ecto` destinations: `webhook.site` (∈ `SUSPICIOUS_DOMAIN_PATTERNS`) + external public IPs
`154.57.164.82/.71` + loopback. Any anomalous host ⇒ not benign ⇒ intent/flow keeps firing,
score 100, T1a. The destination-benignness gate cannot declassify it by construction.

## Implementation consequence
The fix is a **destination-benignness gate** (richer than a literal port of `isSDKPattern`), called
by all three taint detectors. Extract the shared destination logic to a leaf module, add an
AI-provider allowlist + own-domain + loopback/private handling, keep all existing vetoes. Exec-sink
FPs explicitly deferred.
