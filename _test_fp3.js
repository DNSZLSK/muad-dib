const { run } = require('./src/index.js');

(async () => {
  const result = await run(
    'C:/Users/kposz/PyCharmMiscProject/CDA 2025 - 2026/muad-dib/.muaddib-cache/benign-tarballs/vitest/package',
    { _capture: true }
  );

  console.log('Score:', result.summary.riskScore);
  const rs = result.threats.find(t => t.type === 'reverse_shell');
  const ep = result.threats.find(t => t.type === 'env_proxy_intercept');
  console.log('reverse_shell:', rs ? rs.severity : 'not found');
  console.log('env_proxy_intercept:', ep ? ep.severity : 'not found');

  // Show all threats
  result.threats.forEach(t => {
    console.log(`  ${t.severity.padEnd(8)} ${t.type.padEnd(25)} ${t.file}`);
  });
})();
