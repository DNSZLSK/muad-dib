# LLM Triage Design — Architecture Document

## Context

After implementing `computeAlertPriority()` (C2), the monitor classifies alerts into P1/P2/P3.
However, P2 and P3 still produce ~570 alerts/day that require human investigation.
An LLM triage layer can automatically dismiss false positives and surface true threats.

## API

### Input
```json
{
  "target": "npm/evil-pkg@1.0.0",
  "score": 35,
  "riskLevel": "MEDIUM",
  "priority": { "level": "P2", "reason": "lifecycle_plus_intent" },
  "threats": [
    { "type": "lifecycle_script", "severity": "MEDIUM", "message": "preinstall: node setup.js" },
    { "type": "env_access", "severity": "HIGH", "message": "Access to NPM_TOKEN", "file": "setup.js" }
  ],
  "metadata": {
    "packageAge": 2,
    "weeklyDownloads": 0,
    "versionCount": 1,
    "hasRepository": false,
    "unpackedSize": 1200
  }
}
```

### Output
```json
{
  "verdict": "malicious",
  "confidence": 0.95,
  "explanation": "New package (2 days, 0 downloads) with lifecycle hook reading NPM_TOKEN. No repository. Consistent with credential theft pattern.",
  "action": "send_alert",
  "suppressReason": null
}
```

Possible verdicts: `malicious`, `suspicious`, `benign`, `uncertain`
Possible actions: `send_alert`, `suppress`, `escalate_p1`

## Integration Point

```
scanPackage() → computeAlertPriority() → [LLM TRIAGE] → trySendWebhook()
```

- Only P2 and P3 alerts pass through LLM triage
- P1 NEVER passes through LLM — sent immediately (security invariant)
- If LLM is unavailable: fallback to current behavior (send alert as-is)

## Model Selection

| Model | Cost/call | Latency | Quality |
|-------|-----------|---------|---------|
| Claude 3.5 Haiku | ~$0.001 | 1-3s | Sufficient for triage |
| Claude Sonnet | ~$0.005 | 3-8s | Overkill for triage |

**Recommendation:** Claude 3.5 Haiku

**Cost estimate:**
- ~574 P2/P3 alerts/day
- $0.001/call = ~$0.57/day = ~$17/month
- Within acceptable budget for 24/7 monitoring

## Latency Budget

| Priority | Max latency | LLM budget |
|----------|------------|------------|
| P1 | 0s (immediate) | N/A (bypassed) |
| P2 | 30s | 5s LLM + 25s buffer |
| P3 | 5min | 5s LLM + 295s buffer |

## Security Invariants

1. **P1 NEVER suppressed by LLM** — hardware invariant, not configurable
2. **P2 suppressed only if LLM confidence >= 0.9 AND verdict == "benign"**
3. **P3 suppressed if LLM confidence >= 0.8 AND verdict == "benign"**
4. **LLM can escalate P2/P3 to P1** (verdict == "malicious" with confidence >= 0.9)
5. **Rate limit:** max 10 LLM calls/minute to prevent cost runaway
6. **No PII in prompts:** package names and threat types only, no file content

## Phased Rollout

### Phase 3a: Shadow Mode
- LLM runs on all P2/P3 alerts
- Results logged but NOT acted upon
- Metrics: agreement rate with human decisions
- Duration: 2 weeks minimum

### Phase 3b: Enforce P3
- LLM suppresses P3 alerts with high-confidence "benign" verdict
- P2 still sent regardless
- Monitor suppression accuracy daily

### Phase 3c: Enforce P2+P3
- LLM suppresses P2 alerts with very-high-confidence "benign" verdict
- Full automation for routine triage

## Fallback Behavior

- **LLM unavailable** (network error, rate limit, API down): send alert as-is
- **LLM timeout** (>5s): send alert as-is
- **LLM error** (malformed response): send alert as-is + log error
- **LLM verdict "uncertain"**: send alert as-is (conservative)

## Prompt Template (Draft)

```
You are a supply-chain security analyst for npm/PyPI packages.
Analyze this scan alert and determine if it is a true threat or a false positive.

Package: {target}
Risk Score: {score}/100
Priority: {priority.level} ({priority.reason})
Package metadata: age={packageAge} days, downloads={weeklyDownloads}/week, versions={versionCount}

Threats detected:
{threats formatted as bullet list}

Respond with JSON: { "verdict": "...", "confidence": 0.XX, "explanation": "..." }
```

## Dependencies

- C2 (computeAlertPriority) must be implemented first
- Anthropic API key required (env: ANTHROPIC_API_KEY)
- No new npm dependencies (use stdlib https module)

## Metrics to Track

- **Agreement rate:** LLM verdict vs eventual human classification
- **Suppression accuracy:** % of suppressed alerts that were truly benign
- **Cost/day:** actual API spend
- **Latency p50/p95:** LLM call duration
- **Escalation rate:** P2/P3 escalated to P1 by LLM
