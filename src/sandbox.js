const { spawn } = require('child_process');
const path = require('path');

const DOCKER_IMAGE = 'muaddib-sandbox';

async function buildSandboxImage() {
  console.log('[SANDBOX] Building Docker image...');
  
  return new Promise((resolve, reject) => {
    const dockerfilePath = path.join(__dirname, '..', 'docker');
    const proc = spawn('docker', ['build', '-t', DOCKER_IMAGE, dockerfilePath], {
      stdio: 'inherit'
    });
    
    proc.on('close', (code) => {
      if (code === 0) {
        console.log('[SANDBOX] Image built successfully.');
        resolve();
      } else {
        reject(new Error(`Docker build failed with code ${code}`));
      }
    });
    
    proc.on('error', reject);
  });
}

async function runSandbox(packageName) {
  console.log(`\n[SANDBOX] Analyzing "${packageName}" in isolated container...\n`);
  
  const results = {
    package: packageName,
    timestamp: new Date().toISOString(),
    network: [],
    processes: [],
    fileAccess: [],
    suspicious: false,
    threats: []
  };
  
  return new Promise((resolve, reject) => {
    const proc = spawn('docker', [
      'run',
      '--rm',
      '--network=bridge',
      '--memory=512m',
      '--cpus=1',
      '--pids-limit=100',
      DOCKER_IMAGE,
      packageName
    ]);
    
    let output = '';
    let currentSection = null;
    
    proc.stdout.on('data', (data) => {
      const text = data.toString();
      output += text;
      process.stdout.write(text);
      
      // Parse sections
      if (text.includes('=== NETWORK CONNECTIONS ===')) {
        currentSection = 'network';
      } else if (text.includes('=== PROCESS SPAWNS ===')) {
        currentSection = 'processes';
      } else if (text.includes('=== FILE ACCESS ===')) {
        currentSection = 'fileAccess';
      } else if (currentSection && text.trim()) {
        results[currentSection].push(text.trim());
      }
    });
    
    proc.stderr.on('data', (data) => {
      process.stderr.write(data);
    });
    
    proc.on('close', (code) => {
      // Analyze results
      results.suspicious = analyzeResults(results);
      
      if (results.suspicious) {
        console.log('\n[SANDBOX] ⚠️  SUSPICIOUS BEHAVIOR DETECTED!\n');
        for (const threat of results.threats) {
          console.log(`  [${threat.severity}] ${threat.message}`);
        }
      } else {
        console.log('\n[SANDBOX] ✓ No suspicious behavior detected.\n');
      }
      
      resolve(results);
    });
    
    proc.on('error', (err) => {
      if (err.message.includes('ENOENT')) {
        reject(new Error('Docker not found. Please install Docker Desktop.'));
      } else {
        reject(err);
      }
    });
  });
}

function analyzeResults(results) {
  let suspicious = false;
  
  // Check for suspicious network connections
  const suspiciousHosts = ['pastebin', 'discord.com/api/webhooks', 'ngrok', 'burpcollaborator'];
  for (const conn of results.network) {
    for (const host of suspiciousHosts) {
      if (conn.toLowerCase().includes(host)) {
        results.threats.push({
          severity: 'CRITICAL',
          type: 'suspicious_network',
          message: `Connection to suspicious host: ${host}`
        });
        suspicious = true;
      }
    }
  }
  
  // Check for credential file access
  const sensitiveFiles = ['.npmrc', '.ssh', '.aws', '.gitconfig', '.env'];
  for (const access of results.fileAccess) {
    for (const file of sensitiveFiles) {
      if (access.includes(file)) {
        results.threats.push({
          severity: 'HIGH',
          type: 'credential_access',
          message: `Access to sensitive file: ${file}`
        });
        suspicious = true;
      }
    }
  }
  
  // Check for suspicious process spawns
  const suspiciousProcesses = ['curl ', 'wget ', '/nc ', 'netcat', 'bash -c', 'sh -c', 'powershell'];
  for (const proc of results.processes) {
    for (const suspicious_proc of suspiciousProcesses) {
      if (proc.toLowerCase().includes(suspicious_proc)) {
        results.threats.push({
          severity: 'HIGH',
          type: 'suspicious_process',
          message: `Suspicious process spawn: ${suspicious_proc}`
        });
        suspicious = true;
      }
    }
  }
  
  return suspicious;
}

module.exports = { buildSandboxImage, runSandbox };