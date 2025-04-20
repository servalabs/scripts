#!/bin/bash
# ct_backup_manager.sh - Backup Node Contingency Script
# Version: 3.1

set -euo pipefail
trap 'echo "Error on line $LINENO"; exit 1' ERR

# === Constants ===
STATE_FILE="/etc/ct/state.json"
LOG_FILE="/var/log/ct.log"
FLAG_URL="https://ping.servalabs.com/flags/testingzulu1234@gmail.com"

# === Logging Functions ===
log() {
    local level="$1"
    shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $*" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }

# === State Management ===
update_state() {
    local key="$1"
    local value="$2"
    if jq --arg key "$key" --arg value "$value" '.[$key]=$value' "$STATE_FILE" > "$STATE_FILE.tmp"; then
        mv "$STATE_FILE.tmp" "$STATE_FILE"
        log_info "State updated: $key set to $value"
    else
        log_error "Failed to update state key: $key"
        exit 1
    fi
}

init_state() {
    if [ ! -f "$STATE_FILE" ]; then
        cat <<EOF > "$STATE_FILE"
{
  "startup_time": "",
  "syncthing_status": "off",
  "cloudflare_status": "off",
  "cockpit_status": "off",
  "last_transition": "",
  "last_flags_active": "",
  "continuous_inactive_start": "",
  "system_startup_time": ""
}
EOF
        log_info "Initialized state file."
    fi
    
    # Set system startup time if not already set
    local current_startup=$(jq -r '.system_startup_time' "$STATE_FILE")
    if [ -z "$current_startup" ] || [ "$current_startup" == "null" ]; then
        local system_startup=$(uptime -s)
        update_state "system_startup_time" "$system_startup"
        log_info "System startup time recorded: $system_startup"
    fi
}

# === Flag Polling ===
flag_polling() {
    local flags
    flags=$(timeout 5 curl -fsSL "$FLAG_URL")
    if [ -z "$flags" ]; then
        log_error "Failed to retrieve flags from $FLAG_URL"
        exit 1
    fi
    echo "$flags"
}

# === Service Management ===
manage_service() {
    local service="$1"
    local action="$2"
    local state_key="$3"
    
    case "$action" in
        "start")
            if ! systemctl is-active --quiet "$service"; then
                systemctl start "$service" 2>/dev/null || true
                update_state "$state_key" "on"
                log_info "$service started successfully"
            else
                log_info "$service is already running"
            fi
            ;;
        "stop")
            if systemctl is-active --quiet "$service"; then
                systemctl stop "$service" 2>/dev/null || \
                (systemctl kill -s SIGKILL "$service" 2>/dev/null && systemctl stop "$service" 2>/dev/null)
                update_state "$state_key" "off"
                log_info "$service stopped successfully"
            else
                log_info "$service is already stopped"
            fi
            ;;
        "enable")
            if ! systemctl is-enabled --quiet "$service"; then
                systemctl enable --now "$service" 2>/dev/null || true
                update_state "$state_key" "on"
                log_info "$service enabled and started"
            else
                log_info "$service is already enabled"
            fi
            ;;
        "disable")
            if systemctl is-enabled --quiet "$service"; then
                systemctl stop "$service" 2>/dev/null || \
                (systemctl kill -s SIGKILL "$service" 2>/dev/null && systemctl stop "$service" 2>/dev/null)
                systemctl disable "$service" 2>/dev/null || true
                update_state "$state_key" "off"
                log_info "$service disabled and stopped"
            else
                log_info "$service is already disabled"
            fi
            ;;
    esac
}

# === Main Logic ===
init_state
FLAGS_JSON=$(flag_polling)

# Parse all flags in one jq call
F1=$(echo "$FLAGS_JSON" | jq -r '.[] | select(.flagName=="F1") | .enabled')
F2=$(echo "$FLAGS_JSON" | jq -r '.[] | select(.flagName=="F2") | .enabled')
F3=$(echo "$FLAGS_JSON" | jq -r '.[] | select(.flagName=="F3") | .enabled')

log_info "Parsed flags: F1=$F1, F2=$F2, F3=$F3"

# === F1: Shutdown and disable Syncthing (highest priority) ===
if [ "$F1" == "true" ]; then
    log_warn "F1 active: Disabling Syncthing and shutting down."
    manage_service "syncthing" "stop" "syncthing_status"
    log_info "Initiating system shutdown"
    /usr/sbin/shutdown -h now
    exit 0  # Exit immediately after initiating shutdown
fi

# === F3: Enable or Disable Cloudflare and Cockpit (second priority) ===
if [ "$F3" == "true" ]; then
    manage_service "cloudflared" "enable" "cloudflare_status"
    manage_service "cockpit" "enable" "cockpit_status"
    manage_service "cockpit.socket" "enable" "cockpit_status"
else
    manage_service "cloudflared" "disable" "cloudflare_status"
    manage_service "cockpit" "disable" "cockpit_status"
    manage_service "cockpit.socket" "disable" "cockpit_status"
fi

# === F2: Start Syncthing if off (third priority) ===
if [ "$F2" == "true" ]; then
    SYNC_STATUS=$(jq -r '.syncthing_status' "$STATE_FILE")
    if [ "$SYNC_STATUS" != "on" ]; then
        manage_service "syncthing" "start" "syncthing_status"
        log_info "F2 active: Syncthing started."
    else
        log_info "F2 active: Syncthing already running."
    fi
fi

# === Check for continuous inactive state (only if no flags are active) ===
if [ "$F1" != "true" ] && [ "$F2" != "true" ] && [ "$F3" != "true" ]; then
    # Get current time
    NOW=$(date '+%Y-%m-%dT%H:%M:%S')
    
    # Get system startup time
    SYSTEM_STARTUP=$(jq -r '.system_startup_time' "$STATE_FILE")
    SYSTEM_STARTUP_EPOCH=$(date -d "$SYSTEM_STARTUP" +%s)
    CURRENT_EPOCH=$(date +%s)
    UPTIME=$((CURRENT_EPOCH - SYSTEM_STARTUP_EPOCH))
    
    # Update last flags active state
    LAST_FLAGS_ACTIVE=$(jq -r '.last_flags_active' "$STATE_FILE")
    if [ "$LAST_FLAGS_ACTIVE" != "false" ]; then
        update_state "last_flags_active" "false"
        update_state "last_transition" "$NOW"
        # Only set continuous_inactive_start if it's not already set
        CURRENT_INACTIVE_START=$(jq -r '.continuous_inactive_start' "$STATE_FILE")
        if [ -z "$CURRENT_INACTIVE_START" ] || [ "$CURRENT_INACTIVE_START" == "null" ]; then
            update_state "continuous_inactive_start" "$NOW"
        fi
    fi
    
    # Check continuous inactive time
    CONTINUOUS_START=$(jq -r '.continuous_inactive_start' "$STATE_FILE")
    if [ -n "$CONTINUOUS_START" ] && [ "$CONTINUOUS_START" != "null" ]; then
        START_EPOCH=$(date -d "$(echo "$CONTINUOUS_START" | sed 's/T/ /')" +%s)
        ELAPSED=$((CURRENT_EPOCH - START_EPOCH))
        
        if [ "$ELAPSED" -ge 3600 ]; then
            log_info "All flags have been continuously inactive for 1 hour. System uptime: $((UPTIME / 60)) minutes. Shutting down."
            shutdown -h now
            exit 0
        else
            log_info "All flags inactive. Continuous inactive time: $((ELAPSED / 60)) minutes. System uptime: $((UPTIME / 60)) minutes."
        fi
    fi
else
    # Update last flags active state if flags are active
    LAST_FLAGS_ACTIVE=$(jq -r '.last_flags_active' "$STATE_FILE")
    if [ "$LAST_FLAGS_ACTIVE" != "true" ]; then
        update_state "last_flags_active" "true"
        update_state "last_transition" "$(date '+%Y-%m-%dT%H:%M:%S')"
        # Clear continuous_inactive_start when flags become active
        update_state "continuous_inactive_start" ""
    fi
fi

log_info "Execution completed."