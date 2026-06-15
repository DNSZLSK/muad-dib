// Benign CLI dispatcher (gate#2 negative): bounded/local dynamic imports only.
//  - import(p) where p is path.join(localDir, ...) of a whitelisted command file
//  - import(`./layouts/${name}.vue`) — a local relative path, never a remote URL
// No remote URL, no process.env-driven specifier, no runtime decode.
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const SUBCOMMANDS = { up: 'up.js', down: 'down.js', status: 'status.js' };
const here = dirname(fileURLToPath(import.meta.url));

export async function run(cmd) {
  const file = SUBCOMMANDS[cmd];
  const modulePath = join(here, 'commands', file);
  const mod = await import(modulePath);
  return mod;
}

export async function layout(name) {
  return await import(`./layouts/${name}.vue`);
}
