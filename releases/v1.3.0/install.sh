#!/usr/bin/env bash
# vpnweb installer
set -euo pipefail

REPO="https://github.com/username-mendoza/vpnweb.git"
DEFAULT_INSTALL_DIR="/opt/vpnweb"
DEFAULT_PORT="8080"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

# Check once whether /dev/tty is usable (unavailable in Docker/piped installs)
TTY_OK=false
{ true < /dev/tty; } 2>/dev/null && TTY_OK=true || true

ask() {
    $TTY_OK || { warn "Non-interactive — skipping: $1 (defaulting No)"; return 1; }
    local r; read -rp "$1 [y/N] " r < /dev/tty; [[ "$r" =~ ^[Yy]$ ]]
}
prompt() {
    $TTY_OK || { echo "$2"; return; }
    local r; read -rp "$1 " r < /dev/tty; echo "${r:-$2}"
}

echo -e "${BOLD}vpnweb — SoftEther VPN Web Manager${NC}"
echo

[ "$EUID" -eq 0 ] || error "Run as root: sudo bash $0"

# Python check
PY=$(command -v python3 || true)
[ -n "$PY" ] || error "python3 not found — install it first"
PY_VER=$($PY -c 'import sys; print(sys.version_info >= (3,10))')
[ "$PY_VER" = "True" ] || error "Python 3.10+ required (found $($PY --version))"
info "Python: $($PY --version)"

# Ensure venv+ensurepip are available (Debian splits these into python3-venv)
$PY -c 'import ensurepip' 2>/dev/null || {
    warn "python3-venv not found — attempting to install..."
    apt-get install -y python3-venv -qq || error "Could not install python3-venv — install it manually and re-run"
}

# Install directory
INSTALL_DIR=$(prompt "Install directory [$DEFAULT_INSTALL_DIR]:" "$DEFAULT_INSTALL_DIR")

# Source: use repo dir if running from inside it, otherwise clone
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-./}")" 2>/dev/null && pwd || echo ".")"
if [ -f "$SCRIPT_DIR/main.py" ]; then
    info "Installing from $SCRIPT_DIR"
    mkdir -p "$INSTALL_DIR"
    cp -r "$SCRIPT_DIR/." "$INSTALL_DIR/"
else
    info "Cloning from $REPO ..."
    git clone --depth 1 "$REPO" "$INSTALL_DIR"
fi

# Virtual environment — avoids pip PEP 668 (externally-managed-environment) on Debian 12+
VENV="$INSTALL_DIR/.venv"
info "Creating virtualenv at $VENV ..."
$PY -m venv "$VENV"
VENV_PY="$VENV/bin/python3"

info "Installing Python dependencies..."
$VENV_PY -m pip install --quiet fastapi "uvicorn[standard]" httpx cryptography pydantic

# Profiles
if [ ! -f "$INSTALL_DIR/profiles.json" ]; then
    cp "$INSTALL_DIR/profiles.example.json" "$INSTALL_DIR/profiles.json"
    info "Created profiles.json — edit it to add your server(s)"
fi

# Service
if ask "Install as systemd service?"; then
    PORT=$(prompt "Port [$DEFAULT_PORT]:" "$DEFAULT_PORT")

    if ! id vpnweb &>/dev/null 2>&1; then
        useradd -r -s /sbin/nologin -d "$INSTALL_DIR" vpnweb
        info "Created system user: vpnweb"
    fi
    chown -R vpnweb:vpnweb "$INSTALL_DIR"

    cat > /etc/systemd/system/vpnweb.service <<EOF
[Unit]
Description=SoftEther VPN Web Manager
After=network.target

[Service]
Type=simple
User=vpnweb
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_PY -m uvicorn main:app --host 0.0.0.0 --port $PORT
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable vpnweb
    info "Service installed and enabled"

    if ask "Start the service now?"; then
        systemctl start vpnweb
        IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
        info "Started. Open http://$IP:$PORT"
    else
        info "Start when ready: systemctl start vpnweb"
    fi
else
    info "Run manually:"
    echo "  cd $INSTALL_DIR && $VENV_PY -m uvicorn main:app --host 0.0.0.0 --port $DEFAULT_PORT"
fi

echo
info "Done."
