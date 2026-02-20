# Benign Dataset

This dataset contains known-legitimate packages used to measure MUAD'DIB's **False Positive Rate (FPR)**.

## Contents

- `packages-npm.txt` — 100 popular npm packages (one per line)
- `packages-pypi.txt` — 50 popular PyPI packages (one per line)

## FPR Calculation

```
FPR = packages with score > 20 / total packages scanned
```

A package scoring above 20 on a known-legitimate package is considered a false positive.

## Target

**FPR < 5%** — fewer than 8 false positives out of 150 packages.
