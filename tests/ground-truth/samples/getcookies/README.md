# getcookies — Ground Truth Reconstruction

## Source
- https://blog.npmjs.org/post/173526807575/reported-malicious-module-getcookies

## Date
May 2018

## Technique
- Hidden backdoor in seemingly innocent cookie parsing module
- Custom HTTP header triggers code execution (x-forwarded-host with base64 payload)
- eval() for arbitrary code execution from header content
- Secondary backdoor: fetch remote code via HTTPS and execute with new Function()

## What was reconstructed
- Cookie parsing facade (legitimate-looking API)
- Header-based backdoor trigger with base64 decode + eval
- Secondary remote code fetch + execution pattern

## What was simplified
- Original used more layers of indirection in the event-stream dependency chain
- The actual backdoor was more deeply nested in the module hierarchy
