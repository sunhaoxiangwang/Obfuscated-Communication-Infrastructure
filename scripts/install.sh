#!/usr/bin/env bash
set -euo pipefail

# SCF Server Installer — run as root on Ubuntu 22.04/24.04
# Usage: sudo ./scripts/install.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

SCF_USER="scf"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/scf"
OPT_DIR="/opt/scf"

info() { printf '\033[0;32m[+]\033[0m %s\n' "$*"; }
err()  { printf '\033[0;31m[!]\033[0m %s\n' "$*" >&2; }

[[ $EUID -eq 0 ]] || { err "Run as root: sudo $0"; exit 1; }

# ── 1. Service user ──────────────────────────────────────────────
if ! id -u "$SCF_USER" &>/dev/null; then
    info "Creating user: $SCF_USER"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SCF_USER"
else
    info "User $SCF_USER exists"
fi

# ── 2. Binary ────────────────────────────────────────────────────
BIN="$REPO_DIR/target/release/scf-server"
if [[ ! -f "$BIN" ]]; then
    err "Binary not found: $BIN"
    err "Build first:  cargo build --release --features server"
    exit 1
fi
info "Installing binary -> $BIN_DIR/scf-server"
install -m 0755 "$BIN" "$BIN_DIR/scf-server"

# ── 3. Config ────────────────────────────────────────────────────
mkdir -p "$CONFIG_DIR"

if [[ ! -f "$CONFIG_DIR/server.toml" ]]; then
    info "Generating default config -> $CONFIG_DIR/server.toml"
    "$BIN_DIR/scf-server" --generate > "$CONFIG_DIR/server.toml"
    chmod 0640 "$CONFIG_DIR/server.toml"
    chown root:"$SCF_USER" "$CONFIG_DIR/server.toml"
    echo ""
    err ">>> EDIT $CONFIG_DIR/server.toml BEFORE STARTING THE SERVICE <<<"
    echo ""
else
    info "Config exists, not overwriting"
fi

if [[ ! -f "$CONFIG_DIR/scf.env" ]]; then
    install -m 0640 "$REPO_DIR/conf/scf.env.example" "$CONFIG_DIR/scf.env"
    chown root:"$SCF_USER" "$CONFIG_DIR/scf.env"
fi

if [[ ! -f "$CONFIG_DIR/maintenance.conf" ]]; then
    install -m 0644 "$REPO_DIR/conf/maintenance.conf.example" "$CONFIG_DIR/maintenance.conf"
fi

# ── 4. Maintenance script ────────────────────────────────────────
mkdir -p "$OPT_DIR/scripts"
install -m 0755 "$REPO_DIR/scripts/maintenance.sh" "$OPT_DIR/scripts/maintenance.sh"

# ── 5. systemd units ─────────────────────────────────────────────
info "Installing systemd units"
install -m 0644 "$REPO_DIR/systemd/scf-server.service"       /etc/systemd/system/
install -m 0644 "$REPO_DIR/systemd/scf-maintenance.service"  /etc/systemd/system/
install -m 0644 "$REPO_DIR/systemd/scf-maintenance.timer"    /etc/systemd/system/
systemctl daemon-reload

# ── 6. Enable (don't start yet) ──────────────────────────────────
systemctl enable scf-server.service
systemctl enable scf-maintenance.timer

info "Installation complete."
info ""
info "Next steps:"
info "  1. Edit  $CONFIG_DIR/server.toml"
info "  2. Edit  $CONFIG_DIR/scf.env          (log level, etc.)"
info "  3. Edit  $CONFIG_DIR/maintenance.conf  (optional)"
info "  4. systemctl start scf-server"
info "  5. systemctl start scf-maintenance.timer"
info "  6. systemctl status scf-server"
