# polyfill.io — Ground Truth Reconstruction

## Source
- https://sansec.io/research/polyfill-supply-chain-attack

## Date
June 2024

## Technique
- CDN supply chain: acquired polyfill.io domain, modified served JavaScript
- Mobile-only targeting (user agent check) to reduce detection surface
- Referrer-based filtering (exclude search engines)
- Bot/crawler detection to evade security researchers
- Dynamic script injection + meta refresh redirect
- Delayed execution (setTimeout) to evade sandboxes
- Typosquat redirect domains (googie-anaiytics.com)

## What was reconstructed
- Mobile targeting logic
- Bot detection evasion
- Referrer filtering
- Dynamic script injection pattern
- Redirect URL generation with tracking

## What was simplified
- Original attack used heavy obfuscation (variable name mangling)
- CDN-level injection mechanism not reproducible in static analysis
- The actual obfuscated payload was much larger
