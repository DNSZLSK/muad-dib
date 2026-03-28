# MUAD'DIB — Runbook

## 1. VPS DOWN (alerte healthcheck)

```bash
ssh ubuntu@<VPS_IP>
sudo systemctl status muaddib-monitor
```

**Si crashed :**
```bash
sudo journalctl -u muaddib-monitor --since "1 hour ago" | tail -50
sudo systemctl restart muaddib-monitor
```

**Si OOM :**
```bash
free -h
sudo journalctl -u muaddib-monitor | grep -i "killed\|oom\|memory"
sudo systemctl restart muaddib-monitor
```

**Si disk full :**
```bash
df -h
# Purger les tarballs caches (safe — re-telechargement automatique)
rm -rf /opt/muaddib/data/tarball-cache/*
# Purger les vieux backups
ls -lh /opt/muaddib/backups/
rm /opt/muaddib/backups/muaddib-backup-YYYY-MM-DD.tar.gz
sudo systemctl restart muaddib-monitor
```

## 2. ALERTE P1 DISCORD (package suspect)

### Lire l'alerte

Package, score, findings, tier dans l'embed Discord.

### Verifier les metadonnees npm

```bash
# Date creation, maintainer, nombre de versions
curl -s https://registry.npmjs.org/<PACKAGE> | node -e "
  const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
  console.log('created:', d.time?.created);
  console.log('modified:', d.time?.modified);
  console.log('maintainers:', (d.maintainers||[]).map(m=>m.name).join(', '));
  console.log('versions:', Object.keys(d.versions||{}).length);
  console.log('latest:', d['dist-tags']?.latest);
"
```

### Inspecter le code

```bash
cd /tmp
npm pack <PACKAGE>
tar xzf *.tgz
# Lifecycle scripts
node -e "const p=require('./package/package.json'); console.log(JSON.stringify(p.scripts,null,2))"
# Scan des fichiers JS (premiers 50 lignes)
find package/ -name "*.js" -exec head -50 {} \;
# Chercher les patterns suspects
grep -rn "eval\|exec\|spawn\|fetch\|http\|child_process" package/ --include="*.js"
# Cleanup
rm -rf package/ *.tgz
```

### Verifier le repo GitHub

- Date creation du repo
- Nombre de stars/forks
- Historique des commits (recent = suspect)
- Le maintainer npm correspond-il au owner GitHub ?

### Actions

- **Malveillant confirme** : signaler manuellement a `security@npmjs.com` avec le nom du package, la version, et les findings
- **Faux positif** : analyser la cause (regle trop large, pattern benin) et ouvrir une issue si correction necessaire

## 3. DEPLOIEMENT

```bash
cd /opt/muaddib && bash scripts/deploy.sh
```

Voir `docs/DEPLOYMENT.md` pour le detail.

## 4. RESTAURATION BACKUP

```bash
cd /opt/muaddib
ls -lh backups/
tar -xzf backups/muaddib-backup-YYYY-MM-DD.tar.gz
sudo systemctl restart muaddib-monitor
```

Voir `docs/DEPLOYMENT.md` section backup.

## 5. NPM THROTTLE / API CHANGE

```bash
sudo journalctl -u muaddib-monitor --since "10 min ago" | grep -iE "error|timeout|429|ECONNRESET"
```

**Si rate limit (429) :**
```bash
# Reduire la concurrence dans .env
echo "REGISTRY_SEMAPHORE_MAX=3" >> /opt/muaddib/.env
sudo systemctl restart muaddib-monitor
```

**Si API change (parsing errors) :**
```bash
# Verifier manuellement la reponse registry
curl -s https://registry.npmjs.org/-/rss | head -20
curl -s "https://replicate.npmjs.com/_changes?limit=1&descending=true" | head -5
```

Ouvrir une issue sur le repo si le format a change.

## 6. MEMOIRE ELEVEE

```bash
free -h
sudo journalctl -u muaddib-monitor | grep -i "memory\|heap\|rss"
```

**Si peak > 8 Go :**
```bash
# Verifier les sandbox Docker en cours
docker ps
# Tuer un container sandbox bloque
docker kill <CONTAINER_ID>
```

**Si fuite memoire progressive :**
```bash
# Verifier la taille du scan-memory.json (max 50K entries, ~5 MB)
ls -lh /opt/muaddib/data/scan-memory.json
# Verifier la taille du ml-training.jsonl
ls -lh /opt/muaddib/data/ml-training.jsonl
# Redemarrer le monitor (libere les caches in-memory)
sudo systemctl restart muaddib-monitor
```
