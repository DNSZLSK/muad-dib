# MUAD'DIB — Deployment Guide

## Initial VPS Setup

### Fix repo ownership (one-time)

The monitor runs as `ubuntu`. The repo must be owned by this user so that `git pull` (without `sudo`) never clobbers permissions:

```bash
sudo chown -R ubuntu:ubuntu /opt/muaddib
```

After this, **never use `sudo git pull`** — plain `git pull` preserves ownership.

### Verify

```bash
ls -la /opt/muaddib/
# Should show ubuntu:ubuntu for all entries

# Test a pull
cd /opt/muaddib && git pull
ls -la data/
# Should still show ubuntu:ubuntu
```

## Deploy

Use the deploy script for updates — it handles git pull, permissions, dependency install, sandbox rebuild, and service restart:

```bash
cd /opt/muaddib && bash scripts/deploy.sh
```

What it does:
1. `git pull` (no sudo — preserves permissions)
2. Runs `scripts/fix-permissions.sh` (repairs prior root damage on `data/` and `logs/`)
3. Rebuilds Docker sandbox if `docker/` files changed
4. Runs `npm ci` if `package-lock.json` changed
5. Restarts the monitor service
6. Verifies the service is running

Configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `MUADDIB_DIR` | `/opt/muaddib` | Base directory |
| `MUADDIB_SERVICE` | `muaddib-monitor` | Systemd service name |
| `DEPLOY_USER` | `ubuntu` | File owner user |

## Automated Backup

### What is backed up

| File | Description | Size |
|------|-------------|------|
| `data/monitor-state.json` | Monitor poll state (npm seq, last package) | < 1 KB |
| `data/scan-memory.json` | Inter-session dedup (30d, 50K max) | ~1-5 MB |
| `data/ml-training.jsonl` | ML training data from monitor | ~50-100 MB |
| `data/daily-stats/` | Daily report history | ~1 MB |
| `metrics/` | Evaluation metrics per version | ~1 MB |

**Not backed up:** `.env` (contains secrets — manage separately via your secrets manager or document manually).

### Setup

```bash
# Test the backup manually
MUADDIB_DIR=/opt/muaddib bash scripts/backup.sh

# Verify
ls -lh /opt/muaddib/backups/
```

### Systemd timer (recommended)

Create two files on your VPS:

**/etc/systemd/system/muaddib-backup.service**
```ini
[Unit]
Description=MUAD'DIB daily backup
After=network.target

[Service]
Type=oneshot
User=ubuntu
Environment=MUADDIB_DIR=/opt/muaddib
ExecStart=/opt/muaddib/scripts/backup.sh
```

**/etc/systemd/system/muaddib-backup.timer**
```ini
[Unit]
Description=MUAD'DIB daily backup timer

[Timer]
OnCalendar=*-*-* 04:00:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
```

Enable:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now muaddib-backup.timer

# Check status
systemctl list-timers muaddib-backup.timer
journalctl -u muaddib-backup.service --since today
```

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MUADDIB_DIR` | `/opt/muaddib` | Base directory |
| `BACKUP_DIR` | `$MUADDIB_DIR/backups` | Backup storage location |
| `BACKUP_RETAIN` | `7` | Number of daily backups to keep |

### Restore

```bash
# List available backups
ls -lh /opt/muaddib/backups/

# Restore a specific backup
cd /opt/muaddib
tar -xzf backups/muaddib-backup-2026-03-28.tar.gz

# Restart the monitor to pick up restored state
sudo systemctl restart muaddib-monitor
```

### Optional: remote sync

For offsite backup, add an rsync step after the backup script:

```bash
# Scaleway Object Storage (via s3cmd)
s3cmd put /opt/muaddib/backups/muaddib-backup-$(date -u +%Y-%m-%d).tar.gz \
  s3://muaddib-backups/

# Or simple rsync to another server
rsync -az /opt/muaddib/backups/ backup-server:/backups/muaddib/
```

This is not included in the backup script to avoid external dependencies.

## Healthcheck

The monitor can ping an external uptime service (e.g., [Healthchecks.io](https://healthchecks.io)) to detect crashes.

### Setup

1. Create a check on Healthchecks.io (free tier: 20 checks)
2. Set period to **10 minutes**, grace period to **15 minutes**
3. Add to your `.env`:

```bash
MUADDIB_HEALTHCHECK_URL=https://hc-ping.com/your-uuid-here
```

### Behavior

| Event | Ping |
|-------|------|
| Monitor starts | `GET {url}/start` |
| Every 10 min | `GET {url}` |
| Unhandled rejection | `GET {url}/fail` |
| Graceful shutdown (SIGINT/SIGTERM) | No ping (interval stopped) |

If no ping arrives within the grace period, Healthchecks.io sends an alert (email, Slack, PagerDuty, etc.).
