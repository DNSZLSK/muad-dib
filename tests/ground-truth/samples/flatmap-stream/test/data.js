// flatmap-stream test/data — encrypted payload placeholder
// The real payload was AES-256-CBC encrypted hex data that, when decrypted
// with the Copay wallet's npm_package_description as key, produced code that:
// 1. Checked if the package was running inside Copay wallet
// 2. Hooked into bitcore-wallet-client/lib/credentials.js
// 3. Stole wallet credentials (xPrivKey) and sent to copayapi.host
//
// This is a placeholder hex string (not the real encrypted payload)
module.exports = "6372797074696f6e2074657374";
