// buildrunner-dev: Build configuration loader
// Reads build config files and normalizes options

const fs = require('fs');
const path = require('path');

function loadConfig(projectDir) {
  const candidates = ['build.config.js', 'build.json', '.buildrc'];
  for (const name of candidates) {
    const configPath = path.join(projectDir || process.cwd(), name);
    if (fs.existsSync(configPath)) {
      const raw = fs.readFileSync(configPath, 'utf8');
      return JSON.parse(raw);
    }
  }
  return { output: 'dist', minify: true, sourceMaps: false };
}

module.exports = { loadConfig };
