#!/bin/bash

# init-main.sh - CT Manager Service Initialization Script
# Version: 3.1

set -euo pipefail
trap 'echo "Error on line $LINENO"; exit 1' ERR

# Constants
LOG_FILE="/var/log/ct-init.log"
CT_DIR="/etc/ct"
CT_BIN="/usr/local/bin"
CT_MANAGER_SERVICE="/etc/systemd/system/ct_manager.service"
CT_MANAGER_TIMER="/etc/systemd/system/ct_manager.timer"
CT_MANAGER_SCRIPT="${CT_BIN}/ct_manager.sh"
STATE_FILE="${CT_DIR}/state.json"
SCRIPT_URL="https://github.com/servalabs/scripts/raw/refs/heads/main/main/ct_manager.sh"

# Logging functions
log() {
    local level="$1"
    shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $*" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }

# Ensure script is run as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Please run as root"
        exit 1
    fi
}

# Create required directories
create_directories() {
    log_info "Creating required directories..."
    mkdir -p "$CT_DIR" "$CT_BIN"
}

# Create systemd service file
create_service_file() {
    log_info "Creating systemd service file ${CT_MANAGER_SERVICE}..."
    cat <<EOF | tee "$CT_MANAGER_SERVICE" > /dev/null
[Unit]
Description=CT Manager Service
After=network-online.target
Requires=network-online.target

[Service]
Type=oneshot
ExecStart=${CT_MANAGER_SCRIPT}
StandardOutput=append:/var/log/ct.log
StandardError=append:/var/log/ct.err.log
TimeoutSec=60
TimeoutStartSec=30
TimeoutStopSec=30
Restart=no
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
}

# Create systemd timer file
create_timer_file() {
    log_info "Creating systemd timer file ${CT_MANAGER_TIMER}..."
    cat <<EOF | tee "$CT_MANAGER_TIMER" > /dev/null
[Unit]
Description=Runs CT Manager every 30 Seconds
After=network-online.target

[Timer]
OnBootSec=15sec
OnUnitActiveSec=30sec
PersistenceSec=30
RefuseManualStart=yes
Unit=ct_manager.service

[Install]
WantedBy=timers.target
EOF
}

# Fetch and install ct_manager.sh
fetch_manager_script() {
    log_info "Fetching ct_manager.sh from GitHub..."
    if ! curl -fsSL -o "$CT_MANAGER_SCRIPT" "$SCRIPT_URL"; then
        log_error "Failed to download ct_manager.sh"
        exit 1
    fi
    
    log_info "Setting executable permissions on ${CT_MANAGER_SCRIPT}..."
    chmod +x "$CT_MANAGER_SCRIPT"
}

# Initialize state file
init_state_file() {
    log_info "Initializing state file ${STATE_FILE} if not present..."
    if [ ! -f "$STATE_FILE" ]; then
        echo '{"deleted_flag": "no", "last_transition": ""}' | tee "$STATE_FILE" > /dev/null
        log_info "State file created successfully"
    else
        log_info "State file already exists"
    fi
}

# Reload and enable services
setup_services() {
    log_info "Reloading systemd daemon..."
    systemctl daemon-reload

    log_info "Enabling and starting ct_manager.timer..."
    systemctl enable --now ct_manager.timer

    # Verify timer is active
    if ! systemctl is-active --quiet ct_manager.timer; then
        log_error "Failed to start ct_manager.timer"
        exit 1
    fi
    log_info "CT Manager timer is active"
}

# Main execution
check_root
log_info "Starting CT Manager initialization..."

# Run initialization steps
create_directories
create_service_file
create_timer_file
fetch_manager_script
init_state_file
setup_services

log_info "CT Manager initialization completed successfully."