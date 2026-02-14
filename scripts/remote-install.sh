#!/usr/bin/env bash
set -euo pipefail

# SCF Server Remote Installer
# Usage: curl -sSf https://raw.githubusercontent.com/sunhaoxiangwang/Obfuscated-Communication-Infrastructure/main/scripts/remote-install.sh | sudo bash
#
# Downloads the latest release binary, sets up systemd, generates config, and starts the server.
# Requires: Ubuntu 22.04/24.04, root privileges.

REPO="sunhaoxiangwang/Obfuscated-Communication-Infrastructure"
SCF_USER="scf"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/scf"
OPT_DIR="/opt/scf"
SYSTEMD_DIR="/etc/systemd/system"

info() { printf '\033[0;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[0;31m[!]\033[0m %s\n' "$*" >&2; }

[[ $EUID -eq 0 ]] || { err "Run as root: curl ... | sudo bash"; exit 1; }

# ── 1. Detect architecture ──────────────────────────────────────
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ASSET_NAME="scf-server-linux-x86_64" ;;
    aarch64) ASSET_NAME="scf-server-linux-aarch64" ;;
    *) err "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# ── 2. Download latest release ──────────────────────────────────
info "Fetching latest release from GitHub..."
RELEASE_URL=$(curl -sSf "https://api.github.com/repos/$REPO/releases/latest" \
    | grep "browser_download_url.*$ASSET_NAME" \
    | head -1 \
    | cut -d '"' -f 4)

if [ -z "$RELEASE_URL" ]; then
    err "Could not find release asset: $ASSET_NAME"
    err "Check https://github.com/$REPO/releases"
    exit 1
fi

info "Downloading $ASSET_NAME..."
curl -sSfL "$RELEASE_URL" -o /tmp/scf-server
chmod +x /tmp/scf-server

# ── 3. Service user ─────────────────────────────────────────────
if ! id -u "$SCF_USER" &>/dev/null; then
    info "Creating user: $SCF_USER"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SCF_USER"
else
    info "User $SCF_USER exists"
fi

# ── 4. Install binary ───────────────────────────────────────────
info "Installing binary -> $BIN_DIR/scf-server"
install -m 0755 /tmp/scf-server "$BIN_DIR/scf-server"
rm /tmp/scf-server

# ── 5. Config ────────────────────────────────────────────────────
mkdir -p "$CONFIG_DIR"

if [ ! -f "$CONFIG_DIR/server.toml" ]; then
    info "Generating server config -> $CONFIG_DIR/server.toml"
    "$BIN_DIR/scf-server" --generate > "$CONFIG_DIR/server.toml"
    chmod 0640 "$CONFIG_DIR/server.toml"
    chown root:"$SCF_USER" "$CONFIG_DIR/server.toml"
else
    info "Config exists at $CONFIG_DIR/server.toml, not overwriting"
fi

if [ ! -f "$CONFIG_DIR/scf.env" ]; then
    cat > "$CONFIG_DIR/scf.env" <<'ENVEOF'
# Log level: trace | debug | info | warn | error
RUST_LOG=scf=info
ENVEOF
    chmod 0640 "$CONFIG_DIR/scf.env"
    chown root:"$SCF_USER" "$CONFIG_DIR/scf.env"
fi

# ── 6. Maintenance script ───────────────────────────────────────
mkdir -p "$OPT_DIR/scripts"

cat > "$OPT_DIR/scripts/maintenance.sh" <<'MAINTEOF'
#!/usr/bin/env bash
set -euo pipefail
CONF="/etc/scf/maintenance.conf"
[ -f "$CONF" ] && source "$CONF"
# Journal cleanup
journalctl --vacuum-size="${JOURNAL_VACUUM_SIZE:-100M}" --vacuum-time="${JOURNAL_VACUUM_TIME:-7d}" 2>/dev/null || true
# Tmp cleanup
if [ "${CLEAN_TMP:-true}" = "true" ]; then
    find /tmp -type f -atime +"${TMP_MAX_AGE_DAYS:-2}" -delete 2>/dev/null || true
fi
# APT cache
if [ "${CLEAN_APT_CACHE:-true}" = "true" ]; then
    apt-get clean -y 2>/dev/null || true
fi
MAINTEOF
chmod +x "$OPT_DIR/scripts/maintenance.sh"

if [ ! -f "$CONFIG_DIR/maintenance.conf" ]; then
    cat > "$CONFIG_DIR/maintenance.conf" <<'MCONFEOF'
JOURNAL_VACUUM_SIZE="100M"
JOURNAL_VACUUM_TIME="7d"
CLEAN_TMP="true"
TMP_MAX_AGE_DAYS="2"
CLEAN_APT_CACHE="true"
MCONFEOF
fi

# ── 7. systemd units ────────────────────────────────────────────
cat > "$SYSTEMD_DIR/scf-server.service" <<'SVCEOF'
[Unit]
Description=SCF Server (Steganographic Communication Framework)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=scf
Group=scf
ExecStart=/usr/local/bin/scf-server --config /etc/scf/server.toml
Restart=on-failure
RestartSec=5
StartLimitBurst=5
StartLimitIntervalSec=60
EnvironmentFile=-/etc/scf/scf.env
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native
StandardOutput=journal
StandardError=journal
SyslogIdentifier=scf-server

[Install]
WantedBy=multi-user.target
SVCEOF

cat > "$SYSTEMD_DIR/scf-maintenance.service" <<'MSVCEOF'
[Unit]
Description=SCF Maintenance

[Service]
Type=oneshot
ExecStart=/opt/scf/scripts/maintenance.sh
MSVCEOF

cat > "$SYSTEMD_DIR/scf-maintenance.timer" <<'MTEOF'
[Unit]
Description=SCF Maintenance Timer

[Timer]
OnBootSec=15min
OnUnitActiveSec=2h
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
MTEOF

systemctl daemon-reload

# ── 8. Enable and start ─────────────────────────────────────────
systemctl enable scf-server.service
systemctl enable scf-maintenance.timer
systemctl start scf-maintenance.timer
systemctl start scf-server

info ""
info "========================================"
info "  SCF Server installed and running!"
info "========================================"
info ""
info "Next steps:"
info "  1. Add a client:"
info "     sudo scf-server --add-client /etc/scf/server.toml"
info ""
info "  2. Restart to pick up the new client:"
info "     sudo systemctl restart scf-server"
info ""
info "  3. Give the client.json output to your friend"
info ""
info "  4. Check status:"
info "     sudo systemctl status scf-server"
info "     journalctl -u scf-server -f"
info ""
