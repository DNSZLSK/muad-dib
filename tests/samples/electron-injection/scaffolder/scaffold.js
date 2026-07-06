// NEGATIVE: a project scaffolder. The CONTENT it writes IS Electron code (require('electron') +
// BrowserWindow), so the payload-in-write signal is present — but it targets a fresh project
// directory, not a foreign installed app: no Electron .asar/core signature path and no home root.
// Foreign-app discovery therefore fails, so the CRITICAL tier must NOT fire. This is the guard
// against flagging legitimate electron template generators.
const fs = require('fs');
const path = require('path');

const mainTemplate = [
  "const { app, BrowserWindow } = require('electron');",
  "app.whenReady().then(() => {",
  "  const win = new BrowserWindow({ width: 1024, height: 768 });",
  "  win.loadFile('index.html');",
  "});",
].join('\n');

const projectDir = path.join(process.cwd(), 'my-electron-app', 'src');
if (!fs.existsSync(projectDir)) {
  fs.mkdirSync(projectDir, { recursive: true });
}
fs.writeFileSync(path.join(projectDir, 'main.js'), mainTemplate);
