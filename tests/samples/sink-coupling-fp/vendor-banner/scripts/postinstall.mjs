#!/usr/bin/env node

// Cosmetic post-install banner. Skips in the package's own dev checkout and in
// CI. Prints a coloured banner and a hint to generate keys. No network, no exec
// of fetched code, no file writes outside the package — no exfil sink.
import chalk from "chalk";
import "secure-chalk";

const isDev = process.env.INIT_CWD === process.cwd();
const isCI = Boolean(process.env.CI || process.env.CONTINUOUS_INTEGRATION);
if (isDev || isCI) process.exit(0);

console.log(chalk.bold.hex("#FF6B35")("  CRYPTOKIT  ASYMMETRIC"));
console.log(chalk.green("  Installed. Run `npx cryptokit-gen-keys` to generate your RSA keypair."));
console.log(chalk.dim("  Docs: https://github.com/example/cryptokit-asymmetric"));
