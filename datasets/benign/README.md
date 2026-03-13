# Benign Dataset

This dataset contains known-legitimate packages used to measure MUAD'DIB's **False Positive Rate (FPR)**.

## Contents

- `packages-npm.txt` — 532 popular npm packages (one per line)
- `packages-pypi.txt` — 132 popular PyPI packages (one per line)

Package names support version pinning (e.g., `express@4.19.2`) — `npm pack` accepts this format directly.

## FPR Calculation

```
FPR = packages with score > 20 / total packages scanned
```

A package scoring above 20 on a known-legitimate package is considered a false positive.

## Current Results

**FPR ~12.1%** (64/529 npm packages flagged as of v2.6.5).
