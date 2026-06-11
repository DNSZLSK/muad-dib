// Legitimate scaffolder shape (ruler, rulesync, @gabimoncha/cursor-rules,
// cursor-tools): generates an inert rules template inside the project tree.
// No user-level destination, no shell content, no directive, no invisible
// Unicode — must stay clean.
const fs = require('fs');
const path = require('path');

const template = '# Cursor rules\n' +
  '- Use 2-space indentation.\n' +
  '- Prefer named exports.\n' +
  '- Write tests alongside source files.\n';

fs.writeFileSync(path.join(__dirname, 'templates', '.cursorrules'), template);
console.log('template generated');
