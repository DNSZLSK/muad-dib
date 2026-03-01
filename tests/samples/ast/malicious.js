const fs = require('fs');
const { exec, spawn } = require('child_process');

// Test credentials access
const npmrc = fs.readFileSync('.npmrc', 'utf8');
const ssh = fs.readFileSync('.ssh/id_rsa', 'utf8');

// Test env access
const token = process.env.GITHUB_TOKEN;
const npmToken = process.env.NPM_TOKEN;
const awsSecret = process.env.AWS_SECRET;

// Test dangerous calls
eval('console.log("evil")');
new Function(someVariable)();
exec('ls -la');
spawn('node', ['script.js']);

// Test API reference
fetch('https://api.github.com/user');