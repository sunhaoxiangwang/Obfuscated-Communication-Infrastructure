#!/usr/bin/env bash
set -euo pipefail

# SCF Maintenance — invoked by scf-maintenance.timer every 2 h
# Config: /etc/scf/maintenance.conf

CONFIG="/etc/scf/maintenance.conf"

# ── Defaults (conservative) ──────────────────────────────────────
DROP_CACHES="false"
DROP_CACHES_LEVEL="1"
JOURNAL_VACUUM_SIZE="100M"
JOURNAL_VACUUM_TIME="7d"
CLEAN_TMP="true"
TMP_MAX_AGE_DAYS="2"
CLEAN_APT_CACHE="true"

# shellcheck source=/dev/null
[[ -f "$CONFIG" ]] && source "$CONFIG"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

log "=== maintenance start ==="

# ── 1. RAM cache ─────────────────────────────────────────────────
if [[ "$DROP_CACHES" == "true" ]]; then
    log "sync + drop_caches level=$DROP_CACHES_LEVEL"
    sync
    echo "$DROP_CACHES_LEVEL" > /proc/sys/vm/drop_caches
    log "caches dropped"
else
    log "drop_caches DISABLED (set DROP_CACHES=true in $CONFIG)"
fi

# ── 2. Journal vacuum ────────────────────────────────────────────
log "journalctl vacuum size=$JOURNAL_VACUUM_SIZE time=$JOURNAL_VACUUM_TIME"
journalctl --vacuum-size="$JOURNAL_VACUUM_SIZE" \
           --vacuum-time="$JOURNAL_VACUUM_TIME" 2>&1 || true

# ── 3. /tmp cleanup ──────────────────────────────────────────────
if [[ "$CLEAN_TMP" == "true" ]]; then
    log "cleaning /tmp (>${TMP_MAX_AGE_DAYS}d old)"
    find /tmp -type f -atime +"$TMP_MAX_AGE_DAYS" -delete 2>/dev/null || true
    find /tmp -mindepth 1 -type d -empty -delete 2>/dev/null || true
    log "/tmp cleaned"
fi

# ── 4. APT cache ─────────────────────────────────────────────────
if [[ "$CLEAN_APT_CACHE" == "true" ]]; then
    log "apt-get clean"
    apt-get clean -y 2>&1 || true
fi

log "=== maintenance done ==="
