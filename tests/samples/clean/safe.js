// Code normal sans menaces
const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.send('Hello World');
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});

// Safe env vars - should NOT trigger env_access
const env = process.env.NODE_ENV;
const port = process.env.PORT;
const host = process.env.HOST;
const ci = process.env.CI;
const debug = process.env.DEBUG;
const logLevel = process.env.LOG_LEVEL;

// Commentaire mentionnant .npmrc pour test faux positif
// On ne devrait pas detecter: .npmrc, GITHUB_TOKEN, eval