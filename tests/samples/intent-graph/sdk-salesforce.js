// Legitimate Salesforce SDK usage — should NOT trigger intent_credential_exfil
const https = require('https');

const apiKey = process.env.SALESFORCE_API_KEY;

function querySalesforce(soql) {
  const options = {
    hostname: 'login.salesforce.com',
    path: '/services/oauth2/token',
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + apiKey }
  };
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(JSON.parse(data)));
    });
    req.on('error', reject);
    req.end();
  });
}

module.exports = { querySalesforce };
