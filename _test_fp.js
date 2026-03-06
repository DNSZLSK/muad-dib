const { applyFPReductions } = require('./src/scoring.js');

const threats = [
  { type: 'reverse_shell', severity: 'HIGH', message: 'JS reverse shell', file: 'dist\\chunks\\cli-api.js' },
  { type: 'env_proxy_intercept', severity: 'HIGH', message: 'new Proxy(process.env)', file: 'dist\\module-evaluator.js' },
  { type: 'prototype_hook', severity: 'MEDIUM', message: 'WebSocket.prototype.addEventListener', file: 'dist\\chunks\\cli-api.js' }
];

console.log('BEFORE:', threats.map(t => `${t.type}: ${t.severity}`));
applyFPReductions(threats, null, null);
console.log('AFTER:', threats.map(t => `${t.type}: ${t.severity}`));
