// GT fixture: MUADDIB-AST-092 silent_stealth_process.
// Pattern: child_process.spawn() with { detached: true, stdio: 'ignore' }.
// Real malware (TrapDoor build-scripts-utils / async-pipeline-builder, mai 2026)
// uses this combo to survive parent exit AND produce zero observable output.
// Here the command is "true" (POSIX no-op) so the fixture is inert.
const { spawn } = require('child_process');

const child = spawn('true', [], {
  detached: true,
  stdio: 'ignore'
});
child.unref();
