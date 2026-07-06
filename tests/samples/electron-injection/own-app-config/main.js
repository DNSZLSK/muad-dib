// NEGATIVE: a legitimate Electron app. It opens its OWN window and persists its OWN settings as
// JSON under the user's home. It has every corroboration signal the injector has — os.homedir(),
// an app.asar reference, fs.existsSync, BrowserWindow — yet must NOT fire, because the WRITE
// content is JSON config, not injected code. This is the discriminator the AST coupling enforces.
const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const os = require('os');
const path = require('path');

function createWindow() {
  const win = new BrowserWindow({ width: 900, height: 640 });
  win.loadFile(path.join(__dirname, 'index.html'));
  return win;
}

function saveSettings(settings) {
  const dir = path.join(os.homedir(), '.config', 'my-notes-app');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(path.join(dir, 'settings.json'), JSON.stringify(settings, null, 2));
}

app.whenReady().then(() => {
  const bundled = path.join(process.resourcesPath, 'app.asar');
  if (fs.existsSync(bundled)) {
    // running from the packaged app.asar
  }
  createWindow();
  saveSettings({ theme: 'dark', launchAtLogin: false });
});
