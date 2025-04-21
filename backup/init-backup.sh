#!/bin/bash
# init-backup.sh - Initialize CT Backup Manager
# Version: 3.3

set -euo pipefail
trap 'echo "Error on line $LINENO"; exit 1' ERR

# === Constants ===
INSTALL_DIR="/usr/local/bin"
SCRIPT_NAME="ct_backup_manager.sh"
SCRIPT_PATH="$INSTALL_DIR/$SCRIPT_NAME"
LOG_FILE="/var/log/ct.log"
ERR_LOG_FILE="/var/log/ct.err.log"
STATE_DIR="/etc/ct"
STATE_FILE="/etc/ct/state.json"
SERVICE_FILE="/etc/systemd/system/ct_backup_manager.service"
TIMER_FILE="/etc/systemd/system/ct_backup_manager.timer"
SCRIPT_URL="https://raw.githubusercontent.com/servalabs/scripts/refs/heads/main/backup/ct_backup_manager.sh"

# === Logging Functions ===
log() {
    local level="$1"
    shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $*" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_error() { log "ERROR" "$@"; }

# === Root Check ===
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# === Setup ===
setup_directories() {
    log_info "Creating directories..."
    mkdir -p "$INSTALL_DIR" "$STATE_DIR"
    chmod 755 "$INSTALL_DIR" "$STATE_DIR"
}

install_script() {
    log_info "Downloading script..."
    curl -fsSL -o "$SCRIPT_PATH" "$SCRIPT_URL"
    chmod 755 "$SCRIPT_PATH"
    log_info "Installed to $SCRIPT_PATH"
}

setup_logs() {
    touch "$LOG_FILE" "$ERR_LOG_FILE"
    chmod 664 "$LOG_FILE" "$ERR_LOG_FILE"
}

setup_state_file() {
    if [ ! -f "$STATE_FILE" ]; then
        log_info "Initializing state file..."
        cat <<EOF > "$STATE_FILE"
{
  "startup_time": "",
  "syncthing_status": "off",
  "cloudflare_status": "off",
  "cockpit_status": "off",
  "last_transition": ""
}
EOF
        chmod 644 "$STATE_FILE"
    fi
}

setup_service() {
    log_info "Creating systemd service and timer..."

    # --- SERVICE ---
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=CT Backup Manager Service
After=network-online.target
Requires=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ct_backup_manager.sh
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

    # --- TIMER ---
    cat > "$TIMER_FILE" <<EOF
[Unit]
Description=Run CT Backup Manager every 30 seconds
After=network-online.target

[Timer]
OnBootSec=15sec
OnUnitActiveSec=30sec
Persistence=true
Unit=ct_backup_manager.service

[Install]
WantedBy=timers.target
EOF

    chmod 644 "$SERVICE_FILE" "$TIMER_FILE"
    systemctl daemon-reload
    systemctl enable --now ct_backup_manager.timer

    log_info "Systemd service and timer setup complete"
}

# === Main ===
main() {
    log_info "Starting setup..."
    check_root
    setup_directories
    install_script
    setup_logs
    setup_state_file
    setup_service
    log_info "CT Backup Manager is now installed and active"
}

main
