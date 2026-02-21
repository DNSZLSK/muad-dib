# calendar-c2-unicode — Ground Truth Reconstruction

## Source
- https://thehackernews.com/2025/05/malicious-npm-package-leverages-unicode.html

## Date
2025

## Technique
- Unicode steganography: invisible Variation Selector characters encode payload URL
- Google Calendar C2: payload URL hidden in Calendar event's data-base-title attribute
- Base64-encoded URL in Calendar event for dynamic C2 endpoint
- Two-stage: Calendar URL → download → new Function() execution
- Initially benign (5 versions), then malicious update

## What was reconstructed
- Unicode character decoding simulation
- Google Calendar C2 fetch with HTML parsing
- Two-stage payload download and execution
- System info beacon

## What was simplified
- Original used actual invisible Unicode characters (U+E0100-U+E01EF)
- Real Google Calendar event served as C2
- Dependencies: skip-tot, vue-dev-serverr, vue-dummyy, vue-bit
