#!/bin/bash

# init-main.sh - CT Manager Service Initialization Script
# Version: 3.2

set -euo pipefail
trap 'echo "Error on line $LINENO"; exit 1' ERR

# === Constants ===
LOG_FILE="/var/log/ct-init.log"
ERR_LOG_FILE="/var/log/ct-init.err.log"
CT_DIR="/etc/ct"
CT_BIN="/usr/local/bin"
CT_MANAGER_SCRIPT="/usr/local/bin/ct_manager.sh"
CT_MANAGER_SERVICE="/etc/systemd/system/ct_manager.service"
CT_MANAGER_TIMER="/etc/systemd/system/ct_manager.timer"
STATE_FILE="/etc/ct/state.json"
SCRIPT_URL="https://github.com/servalabs/scripts/raw/refs/heads/main/main/ct_manager.sh"

# === Logging Functions ===
log() {
    local level="$1"
    shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $*" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_error() { log "ERROR" "$@"; }

# === Check Root ===
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Please run as root"
        exit 1
    fi
}

# === Directory Setup ===
create_directories() {
    log_info "Creating directories..."
    mkdir -p "$CT_DIR" "$CT_BIN"
    touch "$LOG_FILE" "$ERR_LOG_FILE"
    chmod 755 "$CT_BIN" "$CT_DIR"
    chmod 664 "$LOG_FILE" "$ERR_LOG_FILE"
}

# === Download Script ===
fetch_manager_script() {
    log_info "Fetching ct_manager.sh from GitHub..."
    if curl -fsSL -o "$CT_MANAGER_SCRIPT" "$SCRIPT_URL"; then
        chmod +x "$CT_MANAGER_SCRIPT"
        log_info "Downloaded and installed at $CT_MANAGER_SCRIPT"
    else
        log_error "Failed to download script"
        exit 1
    fi
}

# === Create Service ===
create_service_file() {
    log_info "Creating systemd service file..."
    cat > "$CT_MANAGER_SERVICE" <<EOF
[Unit]
Description=CT Manager Service
After=network-online.target
Requires=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ct_manager.sh
StandardOutput=append:/var/log/ct-init.log
StandardError=append:/var/log/ct-init.err.log
TimeoutSec=60
TimeoutStartSec=30
TimeoutStopSec=30
Restart=no
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "$CT_MANAGER_SERVICE"
}

# === Create Timer ===
create_timer_file() {
    log_info "Creating systemd timer file..."
    cat > "$CT_MANAGER_TIMER" <<EOF
[Unit]
Description=Runs CT Manager every 30 seconds
After=network-online.target

[Timer]
OnBootSec=15sec
OnUnitActiveSec=30sec
Persistence=true
RefuseManualStart=yes
Unit=ct_manager.service

[Install]
WantedBy=timers.target
EOF

    chmod 644 "$CT_MANAGER_TIMER"
}

# === Init State File ===
init_state_file() {
    log_info "Checking for state file..."
    if [ ! -f "$STATE_FILE" ]; then
        echo '{"deleted_flag": "no", "last_transition": ""}' > "$STATE_FILE"
        chmod 644 "$STATE_FILE"
        log_info "State file initialized at $STATE_FILE"
    else
        log_info "State file already exists"
    fi
}

# === Enable & Start Timer ===
setup_services() {
    log_info "Reloading systemd and enabling services..."
    systemctl daemon-reload
    systemctl enable --now ct_manager.timer

    if systemctl is-active --quiet ct_manager.timer; then
        log_info "CT Manager timer is active"
    else
        log_error "Failed to activate CT Manager timer"
        exit 1
    fi
}

# === Main Execution ===
main() {
    check_root
    log_info "Starting CT Manager setup..."
    create_directories
    fetch_manager_script
    create_service_file
    create_timer_file
    init_state_file
    setup_services
    log_info "CT Manager setup completed successfully."
}

main
