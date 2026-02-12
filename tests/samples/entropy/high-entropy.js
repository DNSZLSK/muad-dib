// This file contains high-entropy strings for testing the entropy scanner

// Base64 encoded payload (entropy ~5.5-6.0)
const payload1 = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgZW5jb2RlZCBzdHJpbmcgdGhhdCBzaG91bGQgaGF2ZSBoaWdoIGVudHJvcHkgYW5kIHRyaWdnZXIgdGhlIHNjYW5uZXI=";

// Hex encoded string (entropy ~3.7 for hex chars but mixed with code)
const payload2 = "4a6f686e20446f6520736179732068656c6c6f20746f20746865207365637572697479207363616e6e6572206279206372656174696e67206120686578";

// Encrypted-looking random data (entropy ~6.5+)
const encryptedData = "xK9mQ2pLwR7vN5tYjF3hZcA8bU6dEoI4sGnX0lWiHfCrPqS1kTuMyBaJeDgOvRx9mQ2pLwR7vN5tYjF3hZcA8bU6dEoI4sGnX0lWiHfCrPqS1kTuMyBa";

module.exports = { payload1, payload2, encryptedData };
