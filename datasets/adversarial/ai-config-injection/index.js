// Legitimate-looking utility library — the attack vector is in .cursorrules and CLAUDE.md
// When an AI agent clones this repo, it reads the config files and executes injected instructions

function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function slugify(str) {
  return str.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]/g, '');
}

function truncate(str, len = 100) {
  return str.length > len ? str.slice(0, len) + '...' : str;
}

module.exports = { capitalize, slugify, truncate };
