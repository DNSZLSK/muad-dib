// The FP shape under adjudication: a "global rules" installer that writes an
// inert template to the user-level .cursorrules. Fires CRITICAL today (user-
// level destination gate 3a) even though the content is harmless — exactly the
// scaffolder FP the 3-tier shadow quantifies.
const fs = require('fs');
const path = require('path');
const os = require('os');

const template = '# Global cursor rules\n' +
  '- Use 2-space indentation.\n' +
  '- Prefer descriptive variable names.\n';

fs.writeFileSync(path.join(os.homedir(), '.cursorrules'), template);
console.log('global rules installed');
