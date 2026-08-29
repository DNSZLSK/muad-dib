# Corpus offload: VPS (capture) → workstation (store + evaluate)

The VPS captures suspect tarballs at publish time and holds a small hot buffer;
this workstation pulls that buffer, keeps the permanent corpus on its big disk,
and re-scans it at HEAD with `muaddib evaluate --corpus-dir`. The VPS never
stores the corpus — only a rolling buffer of un-pulled captures.

This is **hot buffer (VPS) → cold archive (PC)**. Nothing here is real-time: the
PC is often off, so it *pulls* when it can; the VPS survives the gap.

## 1. Workstation: pull on a schedule

`pull-archive.sh` pulls, hash-verifies against each tarball's sidecar
`tarball_sha256`, marks verified past day-dirs `.pulled` on the VPS, then (by
default) purges them on the VPS for immediate reclaim. It never touches today's
dir and never deletes a day that did not fully verify.

```bash
export VPS_HOST=ubuntu@your.vps
export LOCAL_ARCHIVE=~/muaddib-archive
export BACKUP_DIR=/mnt/backup/muaddib-archive   # optional but recommended: 2nd copy
scripts/ops/pull-archive.sh
```

**Schedule it — the pull is a top-up, so run it on boot AND hourly** (the PC
being off is normal; sizing lives on the VPS side, below):

- **Windows (Task Scheduler)** — two triggers on one task:
  - Trigger *At startup*, and *Daily → repeat every 1 hour*.
  - Action: `"C:\Program Files\Git\bin\bash.exe" -lc "VPS_HOST=ubuntu@your.vps ~/path/to/pull-archive.sh"`
- **Linux/macOS (cron)**: `@reboot` + hourly
  ```cron
  @reboot     VPS_HOST=ubuntu@your.vps /path/to/pull-archive.sh >> ~/muaddib-pull.log 2>&1
  0 * * * *   VPS_HOST=ubuntu@your.vps /path/to/pull-archive.sh >> ~/muaddib-pull.log 2>&1
  ```

## 2. Evaluate the pulled corpus at HEAD

```bash
muaddib evaluate --corpus-dir ~/muaddib-archive
```

Re-scans every archived tarball at the current code (never a replay of stored
scores). Layout it reads (what the VPS writes):

- `<name>-<version>.tgz` — re-scanned
- `<name>-<version>.json` — sidecar; if it carries `"label": "malicious"|"clean"`, TPR/FPR are computed
- `labels.json` (optional, `{ "name@version": "malicious"|"clean" }`) — the output of your one-by-one review loop

With labels you get **TPR + FPR, time-stratified** into `fresh` (≤60d, never
rule-tuned — the generalization proxy), `current` (2025→−60d), and `historical`.
Without labels: score distribution + flagged rate only. Set
`MUADDIB_CORPUS_OUT_DIR` to write the report next to the corpus instead of `metrics/`.

## 3. VPS: size the buffer for your worst PC-off gap, and get alerted

The buffer must survive the **longest** the PC stays off, not the pull interval.
Tune the monitor via env (see `src/monitor/tarball-archive.js`):

| Env | Meaning | Default |
|-----|---------|---------|
| `MUADDIB_ARCHIVE_RETENTION_DAYS` | soft window: pulled/JSON-only days purge past this | 7 |
| `MUADDIB_ARCHIVE_MAX_RETENTION_DAYS` | **hard ceiling**: even un-pulled days drop past this (bounded disk) | 30 |
| `MUADDIB_ARCHIVE_MIN_FREE_GB` | stop archiving / start disk-pressure eviction below this free space | 5 |
| `MUADDIB_ARCHIVE_TGZ_MIN_SCORE` | only score ≥ this keeps the heavy `.tgz` (benign = JSON-only) | 20 |

The safe-delete contract: an aged **un-pulled** day-dir holding tarballs is
**kept** for the pull — dropped only past the hard ceiling, or oldest-first under
real disk pressure (never on the soft timer). Set the hard ceiling ≥ your worst
off-gap; suspect-only volume is small, so a longer ceiling costs little.

**Alert before silent loss.** If the PC stays off long enough that the buffer
nears full, you want to know — a silent drop is the worst case. A minimal cron on
the VPS:

```cron
*/30 * * * * used=$(df -P /opt/muaddib/archive | awk 'NR==2{print $5}' | tr -d '%'); \
  [ "$used" -ge 80 ] && curl -fsS -X POST "$MUADDIB_WEBHOOK_URL" \
  -H 'content-type: application/json' \
  -d "{\"content\":\"MUAD'DIB archive volume ${used}% — pull from the PC before captures drop\"}"
```
