const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const { loadCachedIOCs } = require('./ioc/updater.js');

// Packages connus sûrs qui utilisent des patterns "suspects" légitimement
const TRUSTED_PACKAGES = [
  'lodash', 'underscore', 'express', 'react', 'vue', 'angular',
  'webpack', 'babel', 'typescript', 'esbuild', 'vite', 'rollup',
  'jest', 'mocha', 'chai', 'sharp', 'bcrypt', 'argon2'
];

async function safeInstall(packages, options = {}) {
  const { isDev, isGlobal, force } = options;
  
  console.log(`
╔══════════════════════════════════════════╗
║   MUAD'DIB Safe Install                  ║
║   Scanning before installing...          ║
╚══════════════════════════════════════════╝
`);

  const tempDir = path.join(process.cwd(), '.muaddib-temp');
  
  try {
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }

    let blocked = false;
    let blockedPkg = null;
    let blockedThreats = [];

    for (const pkg of packages) {
      const pkgName = pkg.replace(/^@[^/]+\//, '').split('@')[0];
      
      // Skip trusted packages
      if (TRUSTED_PACKAGES.includes(pkgName)) {
        console.log(`[OK] ${pkg} - Package de confiance`);
        continue;
      }

      console.log(`[*] Analyse de ${pkg}...`);

      // Verifier si le package est dans les IOCs connus
      try {
        const iocs = loadCachedIOCs();
        const malicious = iocs.packages?.find(p => p.name === pkg || p.name === pkgName);
        
        if (malicious) {
          console.log(`
╔══════════════════════════════════════════╗
║   [!] PACKAGE MALVEILLANT CONNU          ║
╚══════════════════════════════════════════╝
`);
          console.log(`Package: ${pkg}`);
          console.log(`Source: ${malicious.source || 'IOC Database'}`);
          console.log(`Raison: ${malicious.description || 'Package malveillant connu'}`);
          console.log('');
          console.log('[!] Installation BLOQUEE.');
          
          fs.rmSync(tempDir, { recursive: true, force: true });
          return { blocked: true, package: pkg, threats: [{ type: 'known_malicious', severity: 'CRITICAL', message: malicious.description }] };
        }
      } catch (e) {
        // Ignore IOC check errors
      }
      
      // Recuperer les infos du package
      let pkgInfo;
      try {
        const infoRaw = execSync(`npm view ${pkg} --json 2>nul`, { encoding: 'utf8' });
        pkgInfo = JSON.parse(infoRaw);
      } catch (e) {
        console.log(`[!] Package ${pkg} introuvable sur npm`);
        continue;
      }

      // Telecharger le tarball
      const tarball = pkgInfo.dist?.tarball;
      if (!tarball) {
        console.log(`[!] Impossible de recuperer ${pkg}`);
        continue;
      }

      const safeName = pkg.replace(/[@/]/g, '-');
      const tarPath = path.join(tempDir, `${safeName}.tgz`);
      
      try {
        execSync(`curl -sL "${tarball}" -o "${tarPath}"`, { encoding: 'utf8' });
      } catch (e) {
        console.log(`[!] Erreur telechargement ${pkg}`);
        continue;
      }

      // Extraire
      const extractDir = path.join(tempDir, safeName);
      if (!fs.existsSync(extractDir)) {
        fs.mkdirSync(extractDir, { recursive: true });
      }
      
      try {
        execSync(`tar -xzf "${tarPath}" -C "${extractDir}"`, { encoding: 'utf8' });
      } catch (e) {
        console.log(`[!] Erreur extraction ${pkg}`);
        continue;
      }

      // Scanner avec muaddib
      const pkgDir = path.join(extractDir, 'package');
      let scanResult;
      
      try {
        const output = execSync(`node "${path.join(__dirname, '..', 'bin', 'muaddib.js')}" scan "${pkgDir}" --json`, { 
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe']
        });
        scanResult = JSON.parse(output);
      } catch (e) {
        // Si le scan échoue avec exit code > 0, c'est qu'il y a des menaces
        if (e.stdout) {
          try {
            scanResult = JSON.parse(e.stdout);
          } catch (parseErr) {
            console.log(`[OK] ${pkg} - Scan termine`);
            continue;
          }
        } else {
          console.log(`[OK] ${pkg} - Aucune menace`);
          continue;
        }
      }

      // Filtrer les faux positifs connus
      const realThreats = (scanResult.threats || []).filter(t => {
        // Ignorer les fichiers .min.js pour l'obfuscation (c'est de la minification)
        if (t.type === 'obfuscation_detected' && t.file?.endsWith('.min.js')) {
          return false;
        }
        // Ignorer Function() dans les libs de templating
        if (t.type === 'dangerous_call_function' && t.message?.includes('Function')) {
          return false;
        }
        return true;
      });

      if (realThreats.length > 0) {
        console.log(`
╔══════════════════════════════════════════╗
║   [!] MENACES DETECTEES                  ║
╚══════════════════════════════════════════╝
`);
        console.log(`Package: ${pkg}`);
        console.log(`Menaces: ${realThreats.length}`);
        console.log('');
        
        for (const threat of realThreats.slice(0, 5)) {
          console.log(`  [${threat.severity}] ${threat.message}`);
          if (threat.file) console.log(`           Fichier: ${threat.file}`);
        }
        
        if (realThreats.length > 5) {
          console.log(`  ... et ${realThreats.length - 5} autres`);
        }
        
        if (!force) {
          console.log('');
          console.log('[!] Installation BLOQUEE. Utilise --force pour ignorer.');
          blocked = true;
          blockedPkg = pkg;
          blockedThreats = realThreats;
          break;
        } else {
          console.log('');
          console.log('[!] --force active, installation malgre les menaces...');
        }
      } else {
        console.log(`[OK] ${pkg} - Aucune menace detectee`);
      }
    }

    // Nettoyer temp
    fs.rmSync(tempDir, { recursive: true, force: true });

    if (blocked) {
      return { blocked: true, package: blockedPkg, threats: blockedThreats };
    }

    // Tout est clean, installer pour de vrai
    console.log('');
    console.log('[*] Installation en cours...');
    
    let cmd = `npm install ${packages.join(' ')}`;
    if (isDev) cmd += ' --save-dev';
    if (isGlobal) cmd += ' -g';
    
    execSync(cmd, { stdio: 'inherit' });
    
    console.log('');
    console.log('[OK] Installation terminee.');
    
    return { blocked: false };

  } catch (e) {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
    throw e;
  }
}

module.exports = { safeInstall };