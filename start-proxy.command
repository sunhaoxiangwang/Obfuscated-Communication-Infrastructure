#!/bin/bash
# SCF Proxy - Double-click to start
# Automatically configures your Mac to route traffic through the VPS.
# Close this window to stop.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$SCRIPT_DIR/target/release/scf-client"
CONFIG="$SCRIPT_DIR/client.json"

# Raise file descriptor limit
ulimit -n 10240

# Detect the active network service (Wi-Fi or Ethernet)
get_active_service() {
    local services
    services=$(networksetup -listallnetworkservices | tail -n +2)
    while IFS= read -r service; do
        local status
        status=$(networksetup -getinfo "$service" 2>/dev/null | grep "^IP address:" | head -1)
        if [ -n "$status" ]; then
            echo "$service"
            return
        fi
    done <<< "$services"
    echo "Wi-Fi"
}

SERVICE=$(get_active_service)

# Enable SOCKS proxy on the active network interface
enable_proxy() {
    echo "Enabling SOCKS proxy on '$SERVICE'..."
    networksetup -setsocksfirewallproxy "$SERVICE" 127.0.0.1 1080
    networksetup -setsocksfirewallproxystate "$SERVICE" on
}

# Disable SOCKS proxy when we exit
disable_proxy() {
    echo ""
    echo "Disabling SOCKS proxy on '$SERVICE'..."
    networksetup -setsocksfirewallproxystate "$SERVICE" off
    echo "Proxy disabled. You can close this window."
}

trap disable_proxy EXIT

# Check binary exists
if [ ! -f "$CLIENT" ]; then
    echo "Error: scf-client not found at $CLIENT"
    echo "Run: cargo build --release --bin scf-client --features client"
    read -p "Press Enter to close..."
    exit 1
fi

# Check config exists
if [ ! -f "$CONFIG" ]; then
    echo "Error: client.json not found at $CONFIG"
    read -p "Press Enter to close..."
    exit 1
fi

echo "========================================="
echo "  SCF Proxy"
echo "========================================="
echo ""
echo "Network: $SERVICE"
echo ""

enable_proxy

echo ""
echo "Proxy is ON. All traffic is routed through the VPS."
echo "Close this window to stop."
echo ""

"$CLIENT" --config "$CONFIG"

echo ""
echo "Connection ended."
read -p "Press Enter to close..."
