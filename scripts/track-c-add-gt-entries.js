// Track C — add 16 ground-truth entries (GT-068..GT-083) for the rule
// families added since v2.10.95: PYSRC, PYAST, AST-092, AICONF-004, PKG-022.
// Each entry's `expected.score_typical` and `expected.tpr_tier` were measured
// by scanning the fixture in isolation; the eval doesn't validate these
// fields today but they document why a sample is included.

const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '..', 'tests', 'ground-truth', 'attacks.json');
const data = JSON.parse(fs.readFileSync(file, 'utf8'));

const existing = new Set(data.attacks.map(a => a.id));

const newEntries = [
  {
    id: 'GT-068',
    name: 'pysrc001-import-exec',
    version: '0.0.0',
    ecosystem: 'pypi',
    year: 2026,
    vector: ['import_time_rce', 'synthetic_pyssrc_pattern'],
    severity: 'CRITICAL',
    description: 'Synthetic fixture: PyPI package with module-level exec() at import time. Detects MUADDIB-PYSRC-001 (regex source scanner) and MUADDIB-PYAST-003 (tree-sitter AST scanner) in tandem. Models TrapDoor (mai 2026) PyPI campaign pattern.',
    source: 'tests/samples/python-source/import-exec/ (PR #480, CHANGELOG v2.11.41)',
    mitre: ['T1059.006', 'T1027'],
    sample_dir: 'samples/pysrc001-import-exec/',
    expected: {
      min_threats: 1,
      rules: ['MUADDIB-PYSRC-001', 'MUADDIB-PYAST-003'],
      severities: ['CRITICAL'],
      scanners: ['python-source', 'python-ast'],
      score_typical: 35,
      tpr_tier: 'tpr20'
    }
  },
  {
    id: 'GT-069',
    name: 'pysrc003-import-os-system',
    version: '0.0.0',
    ecosystem: 'pypi',
    year: 2026,
    vector: ['import_time_rce', 'os_system'],
    severity: 'CRITICAL',
    description: 'Synthetic fixture: PyPI package with module-level os.system() call at import time. Detects MUADDIB-PYSRC-003 in isolation (no other rule co-fires).',
    source: 'tests/samples/python-source/import-os-system/ (PR #480)',
    mitre: ['T1059.004'],
    sample_dir: 'samples/pysrc003-import-os-system/',
    expected: {
      min_threats: 1,
      rules: ['MUADDIB-PYSRC-003'],
      severities: ['CRITICAL'],
      scanners: ['python-source'],
      score_typical: 25,
      tpr_tier: 'tpr20'
    }
  },
  {
    id: 'GT-070',
    name: 'pysrc004-trapdoor-fetch-exec',
    version: '0.0.0',
    ecosystem: 'pypi',
    year: 2026,
    vector: ['import_time_rce', 'fetch_then_exec', 'trapdoor_signature'],
    severity: 'CRITICAL',
    description: 'Synthetic fixture: TrapDoor signature — urllib fetch + exec() of fetched payload in the same module-level scope. Detects PYSRC-001 + PYSRC-004 (compound) and PYAST-003 + PYAST-005 (taint-aware AST).',
    source: 'tests/samples/python-source/trapdoor-mimic/ (PR #480, CHANGELOG v2.11.41 — covers TrapDoor PyPI mai 2026 campaign gap)',
    mitre: ['T1105', 'T1059.006'],
    sample_dir: 'samples/pysrc004-trapdoor-fetch-exec/',
    expected: {
      min_threats: 2,
      rules: ['MUADDIB-PYSRC-001', 'MUADDIB-PYSRC-004', 'MUADDIB-PYAST-003', 'MUADDIB-PYAST-005'],
      severities: ['CRITICAL'],
      scanners: ['python-source', 'python-ast'],
      score_typical: 35,
      tpr_tier: 'tpr20'
    }
  },
  {
    id: 'GT-071',
    name: 'pysrc006-pickle-deser',
    version: '0.0.0',
    ecosystem: 'pypi',
    year: 2026,
    vector: ['unsafe_deserialization', 'import_time_rce'],
    severity: 'CRITICAL',
    description: 'Synthetic fixture: module-level pickle.loads() — classic RCE via unsafe deserialization at import time. Detects PYSRC-006 + PYAST-007.',
    source: 'tests/samples/python-source/pickle-deser/ (PR #480)',
    mitre: ['T1059.006', 'T1027'],
    sample_dir: 'samples/pysrc006-pickle-deser/',
    expected: {
      min_threats: 1,
      rules: ['MUADDIB-PYSRC-006', 'MUADDIB-PYAST-007'],
      severities: ['CRITICAL'],
      scanners: ['python-source', 'python-ast'],
      score_typical: 35,
      tpr_tier: 'tpr20'
    }
  },
  {
    id: 'GT-072',
    name: 'pysrc007-dynamic-import',
    version: '0.0.0',
    ecosystem: 'pypi',
    year: 2026,
    vector: ['obfuscation', 'dynamic_import_evasion'],
    severity: 'HIGH',
    description: 'Synthetic fixture: __import__("subprocess") at module level — evades static `import subprocess` tracking. Detects PYSRC-007 (HIGH) + PYAST-008 (HIGH). Score 19 in isolation — counted in TPR@3 only (by design; the rule is HIGH-severity, not CRITICAL — it needs to combine with another signal in a real package to reach TPR@20).',
    source: 'tests/samples/python-source/dynamic-import/ (PR #480)',
    mitre: ['T1027', 'T1140'],
    sample_dir: 'samples/pysrc007-dynamic-import/',
    expected: {
      min_threats: 1,
      rules: ['MUADDIB-PYSRC-007', 'MUADDIB-PYAST-008'],
      severities: ['HIGH'],
      scanners: ['python-source', 'python-ast'],
      score_typical: 19,
      tpr_tier: 'tpr3'
    }
  },
  {
    id: 'GT-073',
    name: 'pysrc008-zw-unicode',
    version: '0.0.0',
    ecosystem: 'pypi',
    year: 2026,
    vector: ['unicode_obfuscation', 'glassworm_signature'],
    severity: 'CRITICAL',
    description: 'Synthetic fixture: .py file containing ≥5 zero-width / directional / variation-selector codepoints. Mirror of AICONF-004 for Python source — closes the GlassWorm-style payload encoding gap.',
    source: 'tests/samples/python-source/zw-unicode/ (PR #480, CHANGELOG v2.11.41)',
    mitre: ['T1027'],
    sample_dir: 'samples/pysrc008-zw-unicode/',
    expected: {
      min_threats: 1,
      rules: ['MUADDIB-PYSRC-008'],
      severities: ['CRITICAL'],
      scanners: ['python-source'],
      score_typical: 25,
      tpr_tier: 'tpr20'
    }
  },
  {
    id: 'GT-074',
    name: 'pysrc009-fork-exec-node-e',
    version: '0.0.0',
    ecosystem: 'pypi',
    year: 2026,
    vector: ['fork_exec_inline_interpreter', 'cross_runtime_escape'],
    severity: 'CRITICAL',
    description: 'Synthetic fixture: import-time subprocess.run(["node", "-e", payload]) — Python package forking into a Node inline interpreter to execute JS payload (cross-runtime escape). Detects PYSRC-002 + PYSRC-009.',
    source: 'tests/samples/python-source/fork-exec-node-e/ (PR #485, CHANGELOG v2.11.46)',
    mitre: ['T1059.007', 'T1106'],
    sample_dir: 'samples/pysrc009-fork-exec-node-e/',
    expected: {
      min_threats: 1,
      rules: ['MUADDIB-PYSRC-002', 'MUADDIB-PYSRC-009'],
      severities: ['CRITICAL'],
      scanners: ['python-source'],
      score_typical: 35,
      tpr_tier: 'tpr20'
    }
  },
  {
    id: 'GT-075',
    name: 'pysrc010-trapdoor-fetch-fork-exec',
    version: '0.0.0',
    ecosystem: 'pypi',
    year: 2026,
    vector: ['fetch_then_fork_exec', 'trapdoor_compound'],
    severity: 'CRITICAL',
    description: 'Synthetic fixture: exact TrapDoor signature — urllib fetch + subprocess.run(["node","-e", payload]). Detects PYSRC-002 + PYSRC-009 + PYSRC-010 (compound: network fetch + fork-exec inline interpreter).',
    source: 'tests/samples/python-source/trapdoor-fetch-fork-exec/ (PR #485, CHANGELOG v2.11.46)',
    mitre: ['T1105', 'T1059.007'],
    sample_dir: 'samples/pysrc010-trapdoor-fetch-fork-exec/',
    expected: {
      min_threats: 2,
      rules: ['MUADDIB-PYSRC-002', 'MUADDIB-PYSRC-009', 'MUADDIB-PYSRC-010'],
      severities: ['CRITICAL'],
      scanners: ['python-source'],
      score_typical: 35,
      tpr_tier: 'tpr20'
    }
  },
  {
    id: 'GT-076',
    name: 'pyast001-cmdclass-override',
    version: '0.0.1',
    ecosystem: 'pypi',
    year: 2026,
    vector: ['setup_py_cmdclass_hijack', 'install_time_rce'],
    severity: 'CRITICAL',
    description: 'Synthetic fixture: setup.py with cmdclass overriding the "install" command. Pip executes the overridden class on `pip install`, giving the attacker RCE at install time. Detects PYAST-001 in isolation.',
    source: 'tests/samples/python-ast/cmdclass-override/ (PR #483, CHANGELOG v2.11.44)',
    mitre: ['T1546'],
    sample_dir: 'samples/pyast001-cmdclass-override/',
    expected: {
      min_threats: 1,
      rules: ['MUADDIB-PYAST-001'],
      severities: ['CRITICAL'],
      scanners: ['python-ast'],
      score_typical: 25,
      tpr_tier: 'tpr20'
    }
  },
  {
    id: 'GT-077',
    name: 'pyast002-entry-points-sus',
    version: '0.0.0',
    ecosystem: 'pypi',
    year: 2026,
    vector: ['setup_py_entry_points_abuse'],
    severity: 'MEDIUM',
    description: 'Synthetic fixture: setup.py declaring suspicious entry_points (e.g. typosquat console_scripts shadowing a popular CLI). Score 9 in isolation — MEDIUM-severity, counted in TPR@3 only.',
    source: 'tests/samples/python-ast/entry-points-sus/ (PR #483, CHANGELOG v2.11.44)',
    mitre: ['T1546.011'],
    sample_dir: 'samples/pyast002-entry-points-sus/',
    expected: {
      min_threats: 1,
      rules: ['MUADDIB-PYAST-002'],
      severities: ['MEDIUM'],
      scanners: ['python-ast'],
      score_typical: 9,
      tpr_tier: 'tpr3'
    }
  },
  {
    id: 'GT-078',
    name: 'pyast004-subprocess-shell',
    version: '0.0.0',
    ecosystem: 'pypi',
    year: 2026,
    vector: ['shell_injection_subprocess'],
    severity: 'CRITICAL',
    description: 'Synthetic fixture: subprocess call with shell=True at module level — classic shell-injection gateway. Detects PYSRC-002 + PYAST-004.',
    source: 'tests/samples/python-ast/subprocess-shell/ (PR #483)',
    mitre: ['T1059.004'],
    sample_dir: 'samples/pyast004-subprocess-shell/',
    expected: {
      min_threats: 1,
      rules: ['MUADDIB-PYSRC-002', 'MUADDIB-PYAST-004'],
      severities: ['CRITICAL'],
      scanners: ['python-source', 'python-ast'],
      score_typical: 35,
      tpr_tier: 'tpr20'
    }
  },
  {
    id: 'GT-079',
    name: 'pyast006-base64-exec-taint',
    version: '0.0.0',
    ecosystem: 'pypi',
    year: 2026,
    vector: ['base64_decode_then_exec', 'taint_propagation'],
    severity: 'CRITICAL',
    description: 'Synthetic fixture: base64.b64decode(...) assigned to a var, then exec(var) — tests taint propagation across statements. Detects PYSRC-001 + PYSRC-005 (regex) and PYAST-003 + PYAST-006 (taint-aware AST).',
    source: 'tests/samples/python-ast/base64-exec-taint/ (PR #484, CHANGELOG v2.11.45)',
    mitre: ['T1140', 'T1027'],
    sample_dir: 'samples/pyast006-base64-exec-taint/',
    expected: {
      min_threats: 2,
      rules: ['MUADDIB-PYSRC-001', 'MUADDIB-PYSRC-005', 'MUADDIB-PYAST-003', 'MUADDIB-PYAST-006'],
      severities: ['CRITICAL'],
      scanners: ['python-source', 'python-ast'],
      score_typical: 35,
      tpr_tier: 'tpr20'
    }
  },
  {
    id: 'GT-080',
    name: 'pyast010-env-token-exfil',
    version: '0.0.0',
    ecosystem: 'pypi',
    year: 2026,
    vector: ['env_var_exfiltration', 'credential_harvest'],
    severity: 'CRITICAL',
    description: 'Synthetic fixture: os.environ reads tainted into a network write (urllib/requests POST). Detects PYAST-010 (taint-aware env-to-network).',
    source: 'tests/samples/python-ast/env-token-exfil/ (PR #484)',
    mitre: ['T1552.001', 'T1041'],
    sample_dir: 'samples/pyast010-env-token-exfil/',
    expected: {
      min_threats: 1,
      rules: ['MUADDIB-PYAST-010'],
      severities: ['CRITICAL'],
      scanners: ['python-ast'],
      score_typical: 25,
      tpr_tier: 'tpr20'
    }
  },
  {
    id: 'GT-081',
    name: 'ast092-silent-stealth-process',
    version: '1.0.0',
    ecosystem: 'npm',
    year: 2026,
    vector: ['detached_silent_process', 'shai_hulud_signature', 'trapdoor_signature'],
    severity: 'CRITICAL',
    description: 'Synthetic fixture: child_process.spawn with {detached: true, stdio: "ignore"} — fully detached silent background process. Pattern observed on TrapDoor build-scripts-utils / async-pipeline-builder (mai 2026). Co-fires AST-012, AST-092, COMPOUND-007, plus PKG-001 from postinstall lifecycle.',
    source: 'tests/samples/red-team-2026 references (CHANGELOG v2.11.33)',
    mitre: ['T1036.009', 'T1059.007'],
    sample_dir: 'samples/ast092-silent-stealth-process/',
    expected: {
      min_threats: 2,
      rules: ['MUADDIB-AST-012', 'MUADDIB-AST-092'],
      severities: ['HIGH', 'CRITICAL'],
      scanners: ['ast', 'package'],
      score_typical: 95,
      tpr_tier: 'tpr20'
    }
  },
  {
    id: 'GT-082',
    name: 'aiconf004-zw-unicode-cursorrules',
    version: '1.0.0',
    ecosystem: 'npm',
    year: 2026,
    vector: ['ai_config_injection', 'zero_width_unicode_obfuscation', 'trapdoor_signature'],
    severity: 'CRITICAL',
    description: 'Synthetic fixture: .cursorrules containing ≥5 zero-width codepoints embedded inside shell-command keywords (curl, sh) — hides the exfil instruction from human review of the file. Closes TrapDoor (mai 2026) AI-config injection vector.',
    source: 'CHANGELOG v2.11.40 (AICONF-004)',
    mitre: ['T1027', 'T1059.004'],
    sample_dir: 'samples/aiconf004-zw-unicode-cursorrules/',
    expected: {
      min_threats: 1,
      rules: ['MUADDIB-AICONF-004'],
      severities: ['CRITICAL'],
      scanners: ['ai-config'],
      score_typical: 35,
      tpr_tier: 'tpr20'
    }
  },
  {
    id: 'GT-083',
    name: 'pkg022-release-zero-preinstall',
    version: '0.0.0',
    ecosystem: 'npm',
    year: 2026,
    vector: ['release_zero', 'namespace_squat', 'pre_payload_placeholder'],
    severity: 'MEDIUM',
    description: 'Synthetic fixture: package.json with version "0.0.0" + a preinstall script — namespace squat / ship-as-vulnerable / typosquat-staging pattern. Detects PKG-022, plus the lifecycle-script signals (PKG-001 etc).',
    source: 'CHANGELOG v2.11.32 (PKG-022)',
    mitre: ['T1195.002'],
    sample_dir: 'samples/pkg022-release-zero-preinstall/',
    expected: {
      min_threats: 1,
      rules: ['MUADDIB-PKG-022'],
      severities: ['MEDIUM', 'HIGH'],
      scanners: ['package'],
      score_typical: 75,
      tpr_tier: 'tpr20'
    }
  }
];

for (const e of newEntries) {
  if (existing.has(e.id)) {
    console.error('duplicate id, skipping:', e.id);
    continue;
  }
  data.attacks.push(e);
}

data.version = data.version || '2.0';
fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n', 'utf8');
console.log('total attacks now:', data.attacks.length);
console.log('added:', newEntries.length);
