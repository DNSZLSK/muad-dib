#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# MUAD'DIB Monitor — VPS Setup Script
# Tested on: Ubuntu 24.04 LTS
# =============================================================================

REPO_URL="https://github.com/DNSZLSK/muad-dib.git"
INSTALL_DIR="/opt/muaddib"
SERVICE_USER="muaddib"
SERVICE_FILE="muaddib-monitor.service"
SCRAPE_SERVICE="muaddib-scrape.service"
SCRAPE_TIMER="muaddib-scrape.timer"
SCRAPE_LIGHT_SERVICE="muaddib-scrape-light.service"
SCRAPE_LIGHT_TIMER="muaddib-scrape-light.timer"

echo "============================================"
echo "  MUAD'DIB Monitor — Automated Setup"
echo "============================================"
echo ""

# --- Root check ---
if [ "$(id -u)" -ne 0 ]; then
  echo "[ERROR] This script must be run as root (sudo)."
  exit 1
fi

# --- 1. Install Node.js 20 ---
echo "[1/6] Installing Node.js 20..."
if command -v node &>/dev/null && node -v | grep -q "^v2[0-9]"; then
  echo "  Node.js $(node -v) already installed, skipping."
else
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
  echo "  Installed Node.js $(node -v)"
fi

# --- 2. Install Docker ---
echo "[2/6] Installing Docker..."
if command -v docker &>/dev/null; then
  echo "  Docker already installed, skipping."
else
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io
  systemctl enable docker
  systemctl start docker
  echo "  Docker installed."
fi

# --- 3. Create service user ---
echo "[3/6] Creating user '${SERVICE_USER}'..."
if id "$SERVICE_USER" &>/dev/null; then
  echo "  User '${SERVICE_USER}' already exists, skipping."
else
  useradd --system --shell /usr/sbin/nologin --home-dir "$INSTALL_DIR" "$SERVICE_USER"
  echo "  User '${SERVICE_USER}' created."
fi
usermod -aG docker "$SERVICE_USER"

# --- 4. Clone repository ---
echo "[4/6] Cloning repository to ${INSTALL_DIR}..."
if [ -d "$INSTALL_DIR/.git" ]; then
  echo "  Repository already exists, pulling latest..."
  cd "$INSTALL_DIR"
  git pull --ff-only
else
  git clone "$REPO_URL" "$INSTALL_DIR"
  cd "$INSTALL_DIR"
fi
npm install --production
mkdir -p "$INSTALL_DIR/data"
chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"

# --- 5. Build Docker sandbox image ---
echo "[5/6] Building Docker sandbox image..."
if [ -d "$INSTALL_DIR/docker" ]; then
  docker build -t muaddib-sandbox "$INSTALL_DIR/docker"
  echo "  Sandbox image built."
else
  echo "  No docker/ directory found, skipping sandbox image build."
fi

# --- 6. Install and start systemd service ---
echo "[6/6] Installing systemd service + IOC scrape timers..."
cp "$INSTALL_DIR/deploy/${SERVICE_FILE}" /etc/systemd/system/
cp "$INSTALL_DIR/deploy/${SCRAPE_SERVICE}" /etc/systemd/system/
cp "$INSTALL_DIR/deploy/${SCRAPE_TIMER}" /etc/systemd/system/
cp "$INSTALL_DIR/deploy/${SCRAPE_LIGHT_SERVICE}" /etc/systemd/system/
cp "$INSTALL_DIR/deploy/${SCRAPE_LIGHT_TIMER}" /etc/systemd/system/
systemctl daemon-reload
systemctl enable "$SERVICE_FILE"
systemctl start "$SERVICE_FILE"
# Two timers drive IOC refresh:
#   - muaddib-scrape-light.timer (every 15min): light feeds incl. OSM, Shai-Hulud, Datadog, OSV-API
#   - muaddib-scrape.timer (every 6h): deep refresh incl. OSV zip dumps, OSSF, Aikido, GitHub Advisory
# We enable the .timer units (not the .service units) so systemd schedules them.
systemctl enable "$SCRAPE_LIGHT_TIMER"
systemctl start "$SCRAPE_LIGHT_TIMER"
systemctl enable "$SCRAPE_TIMER"
systemctl start "$SCRAPE_TIMER"

echo ""
echo "============================================"
echo "  Setup complete!"
echo "============================================"
echo ""
echo "  Monitor status:    systemctl status muaddib-monitor"
echo "  Light scrape:      systemctl list-timers muaddib-scrape-light"
echo "  Full scrape:       systemctl list-timers muaddib-scrape"
echo "  View logs:         journalctl -u muaddib-monitor -f"
echo "                     journalctl -u muaddib-scrape-light -f"
echo "                     journalctl -u muaddib-scrape -f"
echo "  Configuration:   /opt/muaddib/.env"
echo ""
echo "  Create /opt/muaddib/.env with:"
echo "    MUADDIB_MONITOR_SANDBOX=true"
echo "    MUADDIB_WEBHOOK_URL=https://hooks.slack.com/services/..."
echo "    # Optional: real-time push of alerts to muad-api dashboard"
echo "    MUADDIB_API_URL=https://api.muaddib.example.com"
echo "    MUADDIB_INGEST_TOKEN=<must match muad-api INGEST_TOKEN>"
echo "    # Optional: OpenSourceMalware.com community feed (60 req/min free tier)"
echo "    OSM_API_TOKEN=osm_<your-token-from-opensourcemalware.com>"
echo ""
