'use strict';

// Ed25519 public key that verifies the ioc-db release manifest (see ioc-db-signature.js).
// Written by scripts/ioc-db-keygen.js; the private key exists only in the `ioc-db` GitHub
// Environment secret IOC_DB_SIGNING_KEY. null = no key yet: every download is refused.
const IOC_DB_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAUfD/0PApe+hdjRWIofTX5vqTme6scIiXXCmCRe6pWbM=\n-----END PUBLIC KEY-----";

module.exports = { IOC_DB_PUBLIC_KEY };
