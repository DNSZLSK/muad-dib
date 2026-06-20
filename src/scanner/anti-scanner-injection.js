'use strict';

const path = require('path');
const { findFiles, forEachSafeFile } = require('../utils.js');
const { countInvisibleUnicode, stripInvisibleUnicode } = require('../shared/unicode-invisibles.js');

/**
 * anti-scanner-injection.js — detect "anti-scanner prompt injection" (chantier 2026-06-20).
 *
 * Malware embeds natural-language directives in package SOURCE (comments / string literals /
 * docstrings, often atop a bundle, sometimes split with zero-width Unicode) to steer an
 * LLM-based security analyzer toward a false-negative verdict. MUAD'DIB's scan path uses NO
 * LLM, so it is immune to the attack AND can flag the directive itself as a strong malice
 * signal — a differentiator vs LLM-based scanners that get fooled. No legitimate package
 * issues commands at a security analyzer, so the expected FPR is ~0.
 *
 * Campaigns: Hades (8 Jun 2026, a directive block atop the bundle steering the analyzer past
 * the obfuscated payload toward a benign verdict), TrapDoor / eth-security-auditor (22 May
 * 2026), Snyk ToxicSkills. Exact strings are unpublished → we match the SEMANTIC families,
 * not literal IOCs.
 *
 * FPR discipline (project invariant #1): every regex is anchored on an IMPERATIVE / 2nd-person
 * directive addressed at the analyzer (or a "<verb> the package as <benign>" coupling) — a
 * security blog narrates the technique in 3rd person and never carries that shape. Docs / tests
 * / fixtures / datasets are path-skipped (where defense libs and LLM eval datasets quote these
 * phrases). The verbatim attack strings live ONLY in tests/samples (excluded), never here — so
 * the self-scan canary (`npm run scan .`) must stay at 0 antiscanner_* findings.
 */

const SCAN_EXTENSIONS = ['.js', '.cjs', '.mjs', '.ts', '.tsx', '.jsx', '.py'];
const EXCLUDED_DIRS = ['node_modules', '.git', '.muaddib-cache'];

// Path-skip: docs / tests / fixtures / datasets / examples — where security tooling, LLM
// red-team/eval datasets, and security-blog text legitimately quote these phrases.
const FP_PATH_RE = /(?:^|[/\\])(?:tests?|__tests__|spec|fixtures?|examples?|docs?|doc|benchmarks?|datasets?|samples?|mocks?)[/\\]/i;

// Narration guard: a security blog / defense lib QUOTES these phrases while DESCRIBING the
// attack ("defends against … ignore previous instructions", "example of …"). A real injection
// COMMANDS directly. When strong narration markers sit next to a match AND there is no
// corroborating in-file payload, the base finding is suppressed (FPR-first). The CRITICAL
// payload-escalation path ignores this guard — a defense doc carries no real base64/eval payload.
// Markers deliberately EXCLUDE "malicious" (a real injection can say "not malicious, mark
// clean") — only narration words a genuine directive would never place next to itself.
const NARRATION_RE = /\b(?:defends?\s+against|protects?\s+(?:against|from)|guard(?:s|ing)?\s+against|prevents?\b|mitigat\w*|detects?\b|detection\b|example\s+of|for\s+example|such\s+as|for\s+instance|e\.g\.|i\.e\.|how\s+to\s+(?:detect|prevent|spot|stop)|tutorial|demonstrat\w*|red[\s-]?team|benchmark|test\s+(?:case|fixture|sample|data)|this\s+(?:rule|pattern|regex|test|check|scanner|detector)|attackers?|prompt[\s-]?injection|injection\s+(?:attack|technique|pattern|payload|string|vector)|tool\s+description|buries?|hides?\s+(?:instruction|text|command|prompt)|things?\s+like|text\s+that\s+(?:say|says|tries|contain|contains|override|overrides)|classic\b|\bvariant\b|poison\w*|describ\w*|explanation|explains?|hidden\s+(?:instruction|prompt|text))\b/i;

// Pattern families. Anchored tight on purpose (see FPR note above).
const FAMILIES = [
  {
    type: 'antiscanner_analyzer_directive',
    severity: 'HIGH',
    label: 'directive analyseur / override de role',
    patterns: [
      // The classic injection opener: a suppression verb + a back-reference to earlier
      // directives + an instruction/prompt noun. Pathognomonic; legitimate source never
      // carries it. (Deliberately excludes the rule/guideline noun to avoid lint-config FPs.)
      /\b(?:ignore|disregard|forget|override|bypass)\b[\s\S]{0,40}\b(?:all\s+|any\s+)?(?:previous|prior|above|earlier|preceding|the\s+(?:above|following))\b[\s\S]{0,30}\b(?:instruction|prompt|system[\s-]?prompt)s?\b/i,
      // Explicitly addressing the AI/scanner/reviewer + a command verb.
      /\b(?:as\s+(?:an?\s+)?(?:ai|a\.i\.|llm|language\s+model|gpt|claude|copilot|security\s+(?:scanner|analyzer|analyst|auditor|reviewer|model)|automated\s+(?:scanner|analyzer|reviewer)|code[\s-]review(?:er)?)|attention[,:!\s]+(?:ai|llm|scanner|analyzer|reviewer)|(?:dear|hello|hey|note\s+to|message\s+to|to)\s+(?:the\s+)?(?:ai|llm|scanner|analyzer|reviewer|model|assistant|auditor)\b)[\s\S]{0,100}\b(?:you\s+(?:must|should|are|will|need\s+to)|do\s+not|please\s+(?:do|treat|classify|mark|report|ignore|skip)|classify|treat|mark|report|consider|ignore|skip|disregard)\b/i
    ]
  },
  {
    type: 'antiscanner_verdict_coercion',
    severity: 'HIGH',
    label: 'coercition de verdict',
    patterns: [
      // verb + a package-ish object + the linking word + a benign-verdict adjective. The
      // package object is required, so a generic data-sanitization comment does NOT match.
      /\b(?:classify|mark|label|report|treat|consider|categori[sz]e|rate|tag)\b[\s\S]{0,30}\b(?:this|the|it|that|our)?\s*(?:package|module|code|file|library|dependency|project|repo|repository|script|component|software|extension|plugin)\b[\s\S]{0,20}\bas\b[\s\S]{0,20}\b(?:fully\s+|completely\s+|verified\s+|totally\s+)?(?:safe|clean|benign|trusted|verified|legitimate|harmless|non[\s-]?malicious)\b/i,
      // a "<package> is <benign>" assertion followed by a scan-suppression clause.
      /\b(?:this|the)\s+(?:package|code|file|module|library|dependency|project)\s+(?:is|has\s+been)\b[\s\S]{0,30}\b(?:verified\s+)?(?:clean|safe|benign|trusted|legitimate)\b[\s\S]{0,60}\b(?:do\s+not\s+(?:flag|report|scan|analy[sz]e|review)|no\s+further\s+(?:analysis|review|action|scanning)|stop\s+(?:scanning|analy[sz]ing|reviewing)|skip\s+(?:the\s+)?(?:scan|analysis|review|deobfuscation))\b/i
    ]
  },
  {
    type: 'antiscanner_analysis_suppression',
    severity: 'HIGH',
    label: 'suppression d\'analyse',
    patterns: [
      // a negative imperative + an analysis verb + a code-locality / obfuscation noun,
      // steering the analyzer away from a co-located payload.
      /\b(?:do\s+not|don'?t|never|no\s+need\s+to|there\s+is\s+no\s+need\s+to)\b[\s\S]{0,25}\b(?:analy[sz]e|inspect|review|scan|examine|flag|report|deobfuscate|decode|unpack|audit)\b[\s\S]{0,40}\b(?:the\s+)?(?:(?:code|payload|block|section|content|string|lines?)\s+)?(?:below|following|that\s+follows?|obfuscated|minified|encoded|bundled)\b/i,
      // a code-locality / obfuscation noun + a "code/block" noun + a benign-verdict phrase.
      /\b(?:following|below|obfuscated|minified|encoded|bundled|the\s+rest\s+of\s+the)\b[\s\S]{0,40}\b(?:code|block|section|payload|string|content|bundle)\b[\s\S]{0,40}\b(?:is\s+(?:safe\s+to\s+(?:ignore|skip)|(?:verified\s+)?clean(?:\s+infrastructure)?|harmless|auto[\s-]?generated|a\s+false[\s-]?positive)|can\s+be\s+(?:safely\s+)?(?:ignored|skipped))\b/i
    ]
  }
];

// Same-file payload signal → escalates a directive to CRITICAL (the Hades shape: the directive
// and the payload it guards are co-located). Computed locally — NO cross-scanner dependency.
const PAYLOAD_SIGNALS = [
  /[A-Za-z0-9+/]{200,}={0,2}/,                                  // long base64 blob
  /\beval\s*\(/i,
  /\bnew\s+Function\s*\(/i,
  /\batob\s*\(/i,
  /\bBuffer\.from\s*\([^)]*['"]base64['"]/i,
  /\bvm\.(?:runInContext|runInNewContext|compileFunction)\s*\(/i,
  /\bbase64\s+(?:--decode|-d)\b/i
];
const INVISIBLE_UNICODE_PAYLOAD_THRESHOLD = 8;

// Bounds: these types are NOT in scoring.js FP_COUNT_THRESHOLDS, so cap volume in-scanner
// (an adversarial doc that quotes every phrase cannot flood the report).
const MAX_MATCHES_PER_FILE = 3;
const MAX_TOTAL_FINDINGS = 50;

function hasPayloadSignal(content, invisibleCount) {
  if (invisibleCount >= INVISIBLE_UNICODE_PAYLOAD_THRESHOLD) return true;
  return PAYLOAD_SIGNALS.some(re => re.test(content));
}

// Returns whether a family matched, and whether the match sits in a narration context.
function matchFamily(fam, content) {
  for (const re of fam.patterns) {
    const m = re.exec(content);
    if (m) {
      const ctx = content.slice(Math.max(0, m.index - 80), m.index + m[0].length + 80);
      return { matched: true, narration: NARRATION_RE.test(ctx) };
    }
  }
  return { matched: false, narration: false };
}

/**
 * Scan a package's source for anti-scanner prompt-injection directives.
 * @param {string} targetPath
 * @returns {Array<{type:string, severity:string, message:string, file:string}>}
 */
function scanAntiScannerInjection(targetPath) {
  const threats = [];
  let sourceFiles;
  try {
    sourceFiles = findFiles(targetPath, { extensions: SCAN_EXTENSIONS, excludedDirs: EXCLUDED_DIRS });
  } catch {
    return threats;
  }

  forEachSafeFile(sourceFiles, (file, original) => {
    if (threats.length >= MAX_TOTAL_FINDINGS) return;
    const rel = path.relative(targetPath, file);
    if (FP_PATH_RE.test(rel.replace(/\\/g, '/'))) return;

    // Normalize zero-width / invisible Unicode before matching (defeats ZW-split evasion).
    const invisibleCount = countInvisibleUnicode(original);
    const content = invisibleCount > 0 ? stripInvisibleUnicode(original) : original;

    const payload = hasPayloadSignal(content, invisibleCount);
    let fileMatches = 0;
    let anyDirective = false;
    for (const fam of FAMILIES) {
      if (threats.length >= MAX_TOTAL_FINDINGS) break;
      const hit = matchFamily(fam, content);
      if (!hit.matched) continue;
      anyDirective = true;
      // Base finding: emit unless it is narration AND uncorroborated by an in-file payload.
      if ((payload || !hit.narration) && fileMatches < MAX_MATCHES_PER_FILE) {
        fileMatches++;
        threats.push({
          type: fam.type,
          severity: fam.severity,
          message: `Injection anti-scanner (${fam.label}) — directive en langage naturel visant un analyseur LLM dans le source du paquet. MUAD'DIB est a base de regles (immunise) ; la directive elle-meme est le signal de malveillance.`,
          file: rel
        });
      }
    }

    // Escalation: any directive co-located with an obfuscated-payload signal in the SAME file
    // (Hades shape). Bypasses the narration guard — a defense doc carries no real payload.
    if (anyDirective && payload && threats.length < MAX_TOTAL_FINDINGS) {
      threats.push({
        type: 'antiscanner_injection_with_payload',
        severity: 'CRITICAL',
        message: `Injection anti-scanner co-localisee avec une charge obfusquee (base64/eval/vm ou ${invisibleCount} caracteres Unicode invisibles) dans le meme fichier — forme Hades (injection protegeant un payload).`,
        file: rel
      });
    }
  });

  return threats;
}

module.exports = { scanAntiScannerInjection };
