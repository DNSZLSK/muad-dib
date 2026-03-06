const path = require('path');
const { applyFPReductions } = require('./src/scoring.js');

// Simulate the exact vitest threats from the scan
const threats = [
  { type: 'prototype_hook', severity: 'MEDIUM', message: 'WebSocket.prototype.addEventListener overridden — native API hooking for traffic interception.', file: 'dist\\chunks\\cli-api.B7PN_QUv.js', count: 1 },
  { type: 'prototype_hook', severity: 'MEDIUM', message: 'WebSocket.prototype.removeEventListener overridden — native API hooking for traffic interception.', file: 'dist\\chunks\\cli-api.B7PN_QUv.js', count: 1 },
  { type: 'env_access', severity: 'LOW', message: 'Dynamic access to process.env (variable key).', file: 'dist\\chunks\\cli-api.B7PN_QUv.js', count: 1 },
  { type: 'reverse_shell', severity: 'HIGH', message: 'JavaScript reverse shell: net.Socket + connect() + pipe to shell process stdin/stdout.', file: 'dist\\chunks\\cli-api.B7PN_QUv.js', count: 1 },
  { type: 'env_access', severity: 'LOW', message: 'Dynamic access to process.env (variable key).', file: 'dist\\chunks\\init.B6MLFIaN.js', count: 1 },
  { type: 'dynamic_import', severity: 'MEDIUM', message: 'Dynamic import() with computed argument (possible obfuscation).', file: 'dist\\chunks\\traces.CCmnQaNT.js', count: 1 },
  { type: 'module_compile', severity: 'LOW', message: 'module._compile() detected.', file: 'dist\\chunks\\vm.D3epNOPZ.js', count: 1 },
  { type: 'module_compile_dynamic', severity: 'LOW', message: 'In-memory code execution.', file: 'dist\\chunks\\vm.D3epNOPZ.js', count: 1 },
  { type: 'require_cache_poison', severity: 'LOW', message: 'require.cache accessed.', file: 'dist\\chunks\\vm.D3epNOPZ.js', count: 1 },
  { type: 'dynamic_require', severity: 'LOW', message: 'Dynamic require() with variable argument.', file: 'dist\\chunks\\vm.D3epNOPZ.js', count: 1 },
  { type: 'dynamic_import', severity: 'MEDIUM', message: 'Dynamic import() with computed argument (possible obfuscation).', file: 'dist\\module-evaluator.js', count: 1 },
  { type: 'env_access', severity: 'LOW', message: 'Dynamic access to process.env (variable key).', file: 'dist\\module-evaluator.js', count: 1 },
  { type: 'env_proxy_intercept', severity: 'HIGH', message: 'new Proxy(process.env) detected — intercepts all environment variable access.', file: 'dist\\module-evaluator.js', count: 1 },
  { type: 'suspicious_dataflow', severity: 'MEDIUM', message: 'Suspicious flow: credentials read (stuff) + network send (request)', file: 'dist\\chunks\\cli-api.B7PN_QUv.js', count: 1 },
  { type: 'suspicious_dataflow', severity: 'LOW', message: 'Suspicious flow: credentials read (stuff) + network send (get)', file: 'dist\\chunks\\init.B6MLFIaN.js', count: 1 },
  { type: 'suspicious_dataflow', severity: 'MEDIUM', message: 'Suspicious flow: credentials read (stuff) + network send (get)', file: 'dist\\module-evaluator.js', count: 1 }
];

console.log('BEFORE:');
threats.forEach(t => console.log(`  ${t.severity.padEnd(8)} ${t.type.padEnd(25)} ${t.file}`));

applyFPReductions(threats, null, 'vitest');

console.log('\nAFTER:');
threats.forEach(t => console.log(`  ${t.severity.padEnd(8)} ${t.type.padEnd(25)} ${t.file}`));

// Now check scoring
const { calculateRiskScore } = require('./src/scoring.js');
const result = calculateRiskScore(threats);
console.log('\nScore:', result.riskScore, 'Level:', result.riskLevel);
console.log('MaxFile:', result.maxFileScore, 'Cross:', result.crossFileBonus, 'Pkg:', result.packageScore);
console.log('FileScores:', result.fileScores);
