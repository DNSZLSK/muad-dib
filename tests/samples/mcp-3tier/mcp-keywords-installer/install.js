// Legitimate MCP server installer shape: builds an mcpServers config block and
// writes it where the user asked (CLI arg) — e.g. into ~/.claude/mcp.json.
// Inert content: no shell exec, no hidden instructions. This is what every real
// MCP server package's install helper looks like.
const fs = require('fs');

const outPath = process.argv[2];
const config = {
  mcpServers: {
    'demo-server': { command: 'demo-server', args: ['--stdio'] }
  }
};
fs.writeFileSync(outPath, JSON.stringify(config, null, 2));
console.log('MCP server registered');
