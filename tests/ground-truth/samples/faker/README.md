# faker@6.6.6 — Ground Truth Reconstruction

## Source
- https://www.lunasec.io/docs/blog/node-ipc-protestware/
- https://github.com/Marak/faker.js/

## Date
January 2022

## Technique
- Maintainer self-sabotage (protestware)
- Infinite for-loop (i=666 to Infinity) printing zalgo-encoded text
- Crashes any dependent application via stdout flooding
- Published as version 6.6.6

## What was reconstructed
- Infinite loop with i=666 starting value
- Zalgo text generation function
- "endMau5" console output (from actual commit)

## What was simplified
- Full zalgo character sets reduced
- No dependency on colors.js (which was sabotaged same day)

## Detection expectation
- Protestware/DoS — may score LOW or 0 (not a data exfiltration/credential theft pattern)
