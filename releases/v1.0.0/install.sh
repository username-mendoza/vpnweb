#!/usr/bin/env bash
set -euo pipefail

# VPN Web Manager install script
# Installs or upgrades to the version in this directory.

VERSION=$(cat "$(dirname "$0")/VERSION")
INSTALL_DIR="/home/mendoza/vpnweb"
SERVICE_NAME="vpnweb"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Colour helpers ─────────────────────────────────────────────────────────────
green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
die()    { red "ERROR: $*"; exit 1; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Run as root (sudo $0)"

green "=== VPN Web Manager v${VERSION} installer ==="

# ── System dependencies ───────────────────────────────────────────────────────
yellow "→ Installing system packages..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv

# ── SoftEther vpncmd check ────────────────────────────────────────────────────
VPNCMD_PATH="/opt/vpnserver/vpncmd"
if [[ ! -x "$VPNCMD_PATH" ]]; then
    yellow "WARNING: vpncmd not found at $VPNCMD_PATH"
    yellow "         Relay server fallback will not work."
    yellow "         Install SoftEther VPN Server to /opt/vpnserver/ to enable it."
fi

# ── Python dependencies ───────────────────────────────────────────────────────
yellow "→ Installing Python packages..."
pip3 install --quiet \
    "fastapi>=0.100.0" \
    "uvicorn[standard]>=0.20.0" \
    "httpx>=0.24.0" \
    "pydantic>=2.0.0"

# ── Application files ─────────────────────────────────────────────────────────
yellow "→ Installing application to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}/static"

cp "${SCRIPT_DIR}/main.py"              "${INSTALL_DIR}/main.py"
cp "${SCRIPT_DIR}/static/index.html"    "${INSTALL_DIR}/static/index.html"
cp "${SCRIPT_DIR}/static/favicon.svg"   "${INSTALL_DIR}/static/favicon.svg"
cp "${SCRIPT_DIR}/static/logo.svg"      "${INSTALL_DIR}/static/logo.svg"

# Create empty profiles.json if not present (preserve existing on upgrade)
if [[ ! -f "${INSTALL_DIR}/profiles.json" ]]; then
    echo '[]' > "${INSTALL_DIR}/profiles.json"
    green "  Created empty profiles.json"
else
    yellow "  Existing profiles.json preserved"
fi

# ── systemd service ───────────────────────────────────────────────────────────
yellow "→ Installing systemd service..."
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=SoftEther VPN Web Manager v${VERSION}
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 -m uvicorn main:app \\
    --host 0.0.0.0 \\
    --port 8443
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}" --quiet

# ── Start / restart service ───────────────────────────────────────────────────
yellow "→ Starting ${SERVICE_NAME}.service..."
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    systemctl restart "${SERVICE_NAME}"
else
    systemctl start "${SERVICE_NAME}"
fi

sleep 2
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    green "=== Installation complete ==="
    green "    Service running on http://0.0.0.0:8443"
    green "    (place HAProxy or nginx in front for HTTPS)"
else
    red "Service failed to start. Check: journalctl -u ${SERVICE_NAME} -n 30"
    exit 1
fi
