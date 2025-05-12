#!/bin/bash
# ct.sh - Consolidated Contingency System Manager
# Version: 1.0.1
# This script consolidates all functions for the CT system:
# - Monitoring for flags and executing appropriate actions
# - Self-updating from GitHub repository
# - Directly executing operations (destroy, restore, support, support-disable)

set -euo pipefail
trap 'echo "Error on line $LINENO in function ${FUNCNAME[0]}" >> "$LOG_FILE"' ERR

# ============================
# === Configuration ===
# ============================
CT_DIR="/etc/ct"
LOG_DIR="/var/log"
LOG_FILE="${LOG_DIR}/ct.log"
ERROR_LOG_FILE="${LOG_DIR}/ct.err.log"
STATE_FILE="${CT_DIR}/state.json"
NODE_CONFIG="${CT_DIR}/node.conf"
FLAG_URL="https://ping.servalabs.com/flags/testingzulu1234@gmail.com"
SENSITIVE_DIR="/files/20 Docs"
SCRIPT_URL="https://raw.githubusercontent.com/servalabs/scripts/main/ct.sh"
SCRIPT_PATH="$0"
CURRENT_VERSION="1.0.1"
LOCK_FILE="${CT_DIR}/.lock"
INSTANCE_LOCK="/tmp/ct_script.lock"

# Ensure log files exist
touch "${LOG_FILE}" "${ERROR_LOG_FILE}"
chmod 644 "${LOG_FILE}" "${ERROR_LOG_FILE}"

# Check if system was recently booted (less than 2 minutes ago)
boot_time=$(cat /proc/uptime | awk '{print $1}' | cut -d. -f1)
if [ "$boot_time" -lt 120 ]; then
    # System recently booted, forcibly remove any stale lock file
    rm -f "${INSTANCE_LOCK}"
    log_info "System recently booted. Removed any stale lock file."
fi

# Check if another instance is running
if [ -e "${INSTANCE_LOCK}" ]; then
    pid=$(cat "${INSTANCE_LOCK}" 2>/dev/null || echo "")
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "Another instance is already running (PID: $pid). Exiting."
        exit 0
    else
        # Stale lock file - remove it
        rm -f "${INSTANCE_LOCK}"
    fi
fi

# Create instance lock with a 5-minute timeout
echo $$ > "${INSTANCE_LOCK}"
trap 'rm -f "${INSTANCE_LOCK}"; echo "Error on line $LINENO in function ${FUNCNAME[0]}" >> "$LOG_FILE"' ERR
trap 'rm -f "${INSTANCE_LOCK}"' EXIT INT TERM

# Add a timeout to automatically remove stale locks
(
    sleep 300  # 5 minutes
    if [ -e "${INSTANCE_LOCK}" ]; then
        lock_pid=$(cat "${INSTANCE_LOCK}" 2>/dev/null || echo "")
        if [ "$lock_pid" = "$$" ]; then
            rm -f "${INSTANCE_LOCK}"
        fi
    fi
) &

# ============================
# === Lock Management ===
# ============================
acquire_lock() {
    local lockfile="$1"
    local timeout=300  # 5 minutes timeout
    local start_time=$(date +%s)
    
    while [ $(($(date +%s) - start_time)) -lt $timeout ]; do
        if mkdir "$lockfile" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

release_lock() {
    local lockfile="$1"
    rmdir "$lockfile" 2>/dev/null || true
}

# ============================
# === Logging Functions ===
# ============================
log() {
    local level="$1"
    shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $*" >> "${LOG_FILE}"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_success() { log "SUCCESS" "$@"; }

# ============================
# === Common Utility Functions ===
# ============================

# Get the node type (main or backup)
get_node_type() {
    if [ -f "${NODE_CONFIG}" ]; then
        cat "${NODE_CONFIG}"
    else
        log_error "Node configuration file not found at ${NODE_CONFIG}"
        exit 1
    fi
}

# Update a field in the state JSON file with locking
update_state() {
    local key="$1"
    local value="$2"
    
    if ! acquire_lock "${LOCK_FILE}"; then
        log_error "Failed to acquire lock for state update"
        return 1
    fi
    
    if jq --arg key "$key" --arg value "$value" '.[$key]=$value' "${STATE_FILE}" > "${STATE_FILE}.tmp"; then
        mv "${STATE_FILE}.tmp" "${STATE_FILE}"
        log_info "State updated: ${key} set to ${value}"
    else
        log_error "Failed to update state for key ${key}"
        release_lock "${LOCK_FILE}"
        return 1
    fi
    
    release_lock "${LOCK_FILE}"
    return 0
}

# Initialize the state file if it doesn't exist
init_state() {
    local node_type=$(get_node_type)
    
    if ! acquire_lock "${LOCK_FILE}"; then
        log_error "Failed to acquire lock for state initialization"
        return 1
    fi
    
    if [ ! -f "${STATE_FILE}" ]; then
        if [ "${node_type}" == "main" ]; then
            echo '{"deleted_flag": "no", "last_transition": ""}' > "${STATE_FILE}"
        else
            echo '{"startup_time": "", "syncthing_status": "off", "cloudflare_status": "off", "cockpit_status": "off", "last_transition": "", "last_flags_active": "", "continuous_inactive_start": "", "system_startup_time": ""}' > "${STATE_FILE}"
        fi
        chmod 644 "${STATE_FILE}"
        log_info "Initialized state file for ${node_type} node"
    fi
    
    # Set system startup time for backup node if not already set
    if [ "${node_type}" == "backup" ]; then
        local current_startup=$(jq -r '.system_startup_time' "${STATE_FILE}")
        if [ -z "${current_startup}" ] || [ "${current_startup}" == "null" ]; then
            local system_startup=$(uptime -s)
            update_state "system_startup_time" "${system_startup}"
            log_info "System startup time recorded: ${system_startup}"
        fi
    fi
    
    release_lock "${LOCK_FILE}"
}

# Retrieve the flags from the remote dashboard with retry
fetch_flags() {
    local max_retries=3
    local retry_count=0
    local backoff=1
    
    while [ $retry_count -lt $max_retries ]; do
        local flags=$(timeout 10 curl -fsSL "${FLAG_URL}")
        if [ $? -eq 0 ] && [ -n "${flags}" ]; then
            log_info "Flags retrieved successfully"
            echo "${flags}"
            return 0
        fi
        
        retry_count=$((retry_count + 1))
        sleep $backoff
        backoff=$((backoff * 2))
    done
    
    log_error "Failed to retrieve flags after ${max_retries} attempts"
    return 1
}

# Parse flags from the JSON response
parse_flags() {
    local flags_json="$1"
    
    # Parse F1, F2, F3 flags
    local f1=$(echo "${flags_json}" | jq -r '.[] | select(.flagName=="F1") | .enabled')
    local f2=$(echo "${flags_json}" | jq -r '.[] | select(.flagName=="F2") | .enabled')
    local f3=$(echo "${flags_json}" | jq -r '.[] | select(.flagName=="F3") | .enabled')
    
    # Log the flag values
    log_info "Parsed flags: F1=${f1}, F2=${f2}, F3=${f3}"
    
    # Return as a space-separated string
    echo "${f1} ${f2} ${f3}"
}

# ============================
# === Service Management Functions ===
# ============================

# Manage a service with proper state verification
manage_service() {
    local service="$1"
    local action="$2"
    local state_key="$3"
    local timeout=30
    local start_time=$(date +%s)
    
    log_info "Managing service ${service}: ${action}"
    
    case "${action}" in
        "start")
            if ! systemctl is-active --quiet "${service}"; then
                systemctl start "${service}" 2>/dev/null || true
                
                # Wait for service to be active
                while [ $(($(date +%s) - start_time)) -lt $timeout ]; do
                    if systemctl is-active --quiet "${service}"; then
                        [ -n "${state_key}" ] && update_state "${state_key}" "on"
                        log_info "${service} started successfully"
                        return 0
                    fi
                    sleep 1
                done
                log_error "${service} failed to start within ${timeout} seconds"
                return 1
            else
                log_info "${service} is already running"
            fi
            ;;
        "stop")
            if systemctl is-active --quiet "${service}"; then
                systemctl stop "${service}" 2>/dev/null || \
                (systemctl kill -s SIGKILL "${service}" 2>/dev/null && systemctl stop "${service}" 2>/dev/null)
                
                # Wait for service to be inactive
                while [ $(($(date +%s) - start_time)) -lt $timeout ]; do
                    if ! systemctl is-active --quiet "${service}"; then
                        [ -n "${state_key}" ] && update_state "${state_key}" "off"
                        log_info "${service} stopped successfully"
                        return 0
                    fi
                    sleep 1
                done
                log_error "${service} failed to stop within ${timeout} seconds"
                return 1
            else
                log_info "${service} is already stopped"
            fi
            ;;
        "enable")
            if ! systemctl is-enabled --quiet "${service}"; then
                systemctl enable --now "${service}" 2>/dev/null || true
                
                # Wait for service to be active
                while [ $(($(date +%s) - start_time)) -lt $timeout ]; do
                    if systemctl is-active --quiet "${service}"; then
                        [ -n "${state_key}" ] && update_state "${state_key}" "on"
                        log_info "${service} enabled and started"
                        return 0
                    fi
                    sleep 1
                done
                log_error "${service} failed to start within ${timeout} seconds"
                return 1
            else
                log_info "${service} is already enabled"
            fi
            ;;
        "disable")
            if systemctl is-enabled --quiet "${service}"; then
                systemctl stop "${service}" 2>/dev/null || \
                (systemctl kill -s SIGKILL "${service}" 2>/dev/null && systemctl stop "${service}" 2>/dev/null)
                systemctl disable "${service}" 2>/dev/null || true
                
                # Wait for service to be inactive
                while [ $(($(date +%s) - start_time)) -lt $timeout ]; do
                    if ! systemctl is-active --quiet "${service}"; then
                        [ -n "${state_key}" ] && update_state "${state_key}" "off"
                        log_info "${service} disabled and stopped"
                        return 0
                    fi
                    sleep 1
                done
                log_error "${service} failed to stop within ${timeout} seconds"
                return 1
            else
                log_info "${service} is already disabled"
            fi
            ;;
    esac
}

# Check if services are running with proper verification
services_running() {
    local services=("tailscaled" "syncthing" "cloudflared" "cockpit" "cockpit.socket" "casaos-gateway")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log_info "Service $service is running"
            return 0  # At least one service is running
        fi
    done
    
    log_info "No monitored services are running"
    return 1  # No services are running
}

# ============================
# === File Management Functions ===
# ============================

# Check if sensitive files exist with proper error handling
sensitive_files_exist() {
    if [ ! -d "${SENSITIVE_DIR}" ]; then
        log_info "No sensitive directory found at ${SENSITIVE_DIR}"
        return 1
    fi

    # Check if we can read the directory
    if [ ! -r "${SENSITIVE_DIR}" ]; then
        log_error "Cannot read sensitive directory ${SENSITIVE_DIR}"
        return 1
    fi

    # Get list of files excluding .stfolder
    local files
    files=$(ls -A "${SENSITIVE_DIR}" 2>/dev/null | grep -v "^.stfolder$")
    
    if [ -n "${files}" ]; then
        log_info "Sensitive files found in ${SENSITIVE_DIR}"
        return 0  # Sensitive files exist
    else
        # Only .stfolder exists or directory is empty
        if [ -d "${SENSITIVE_DIR}/.stfolder" ]; then
            log_info "Only .stfolder exists in ${SENSITIVE_DIR}"
        else
            log_info "Directory ${SENSITIVE_DIR} is completely empty"
        fi
        return 1
    fi
}

# ============================
# === Operation Functions ===
# ============================

# Simple retry mechanism for failed operations with exponential backoff
retry_operation() {
    local operation="$1"
    local max_retries=3
    local retry_count=0
    local backoff=1
    
    while [ $retry_count -lt $max_retries ]; do
        log_info "Retrying $operation (attempt $((retry_count + 1))/$max_retries)"
        
        case "$operation" in
            "destroy")
                # Try to stop services again with more force
                log_info "Forcefully stopping services"
                systemctl kill -s SIGKILL tailscaled 2>/dev/null || true
                systemctl stop tailscaled 2>/dev/null || true
                systemctl kill -s SIGKILL syncthing 2>/dev/null || true
                systemctl stop syncthing cloudflared cockpit cockpit.socket casaos-gateway 2>/dev/null || true
                ;;
            "restore")
                # Try to start critical services
                systemctl start tailscaled syncthing 2>/dev/null || true
                ;;
            *)
                log_error "Unknown operation type: $operation"
                return 1
                ;;
        esac
        
        # Wait with exponential backoff
        sleep $backoff
        backoff=$((backoff * 2))
        
        # Check if services are in expected state
        if [ "$operation" = "destroy" ] && ! services_running; then
            log_success "Destroy operation successful after retry"
            return 0
        elif [ "$operation" = "restore" ] && services_running; then
            log_success "Restore operation successful after retry"
            return 0
        fi
        
        retry_count=$((retry_count + 1))
    done
    
    log_error "Failed to complete $operation after $max_retries attempts"
    return 1
}

# MAIN NODE: Destroy Function - Secure erase files and stop services
main_destroy() {
    log_info "Starting destroy operation for main node"
    
    # First stop Tailscale specifically
    log_info "Stopping Tailscale service"
    manage_service "tailscaled" "stop" ""
    
    # Then stop Syncthing specifically
    log_info "Stopping Syncthing service"
    manage_service "syncthing" "stop" ""
    
    # Define all other services to stop
    local services=(
        "cloudflared"
        "cockpit"
        "cockpit.socket"
        "casaos-gateway"
    )
    
    # Stop all other services in parallel
    for service in "${services[@]}"; do
        manage_service "${service}" "stop" "" &
    done
    
    # Wait for all background processes to complete
    wait
    
    # If services are still running, try to force stop them
    if services_running; then
        log_warn "Some services still running, attempting forced stop"
        retry_operation "destroy"
    fi
    
    # Handle sensitive files
    if [ -d "${SENSITIVE_DIR}" ]; then
        log_info "Securely erasing files in ${SENSITIVE_DIR}"
        # Securely erase all files except .stfolder
        find "${SENSITIVE_DIR}" -mindepth 1 -maxdepth 1 -not -name ".stfolder" -type f -exec shred -u -n 1 -z {} \;
        # Remove any remaining directories (except .stfolder)
        find "${SENSITIVE_DIR}" -mindepth 1 -maxdepth 1 -not -name ".stfolder" -type d -exec rm -rf {} \;
        log_info "Successfully securely erased all contents while preserving .stfolder"
    else
        log_info "Target directory ${SENSITIVE_DIR} does not exist"
    fi
    
    log_success "Destroy operation completed for main node"
}

# BACKUP NODE: Destroy Function - Stop Syncthing and prepare for shutdown
backup_destroy() {
    log_info "Starting destroy operation for backup node"
    
    # Stop Syncthing service
    manage_service "syncthing" "stop" "syncthing_status"
    
    log_success "Destroy operation completed for backup node"
}

# MAIN NODE: Restore Function - Restore services
main_restore() {
    log_info "Starting restore operation for main node"
    
    # Define services to restore
    local services=(
        "tailscaled"           # Network first
        "syncthing"            # File sync
        "casaos-gateway.service"
    )
    
    # Restore services
    for service in "${services[@]}"; do
        manage_service "${service}" "enable" ""
    done
    
    # Check if services started successfully
    if ! services_running; then
        log_warn "Some services failed to start, attempting retry"
        retry_operation "restore"
    fi
    
    log_success "Restore operation completed for main node"
}

# BACKUP NODE: Restore Function - Start Syncthing
backup_restore() {
    log_info "Starting restore operation for backup node"
    
    # Start Syncthing service
    manage_service "syncthing" "start" "syncthing_status"
    
    log_success "Restore operation completed for backup node"
}

# MAIN NODE: Support Function - Enable remote access services
main_support() {
    log_info "Starting support operation for main node"
    
    # Define support services
    local services=(
        "cloudflared"
        "cockpit"
        "cockpit.socket"
    )
    
    # Check which services need to be enabled
    local services_to_enable=()
    for service in "${services[@]}"; do
        if ! systemctl is-enabled --quiet "${service}" 2>/dev/null; then
            services_to_enable+=("${service}")
        fi
    done
    
    # Only take action if there are services to enable
    if [ ${#services_to_enable[@]} -eq 0 ]; then
        log_info "All support services are already enabled"
    else
        # Enable and start all support services that need it
        for service in "${services_to_enable[@]}"; do
        manage_service "${service}" "enable" ""
    done
    fi
    
    log_success "Support operation completed for main node"
}

# BACKUP NODE: Support Function - Enable remote access services
backup_support() {
    log_info "Starting support operation for backup node"
    
    # Enable and start support services
    manage_service "cloudflared" "enable" "cloudflare_status"
    manage_service "cockpit" "enable" "cockpit_status"
    manage_service "cockpit.socket" "enable" "cockpit_status"
    
    log_success "Support operation completed for backup node"
}

# Main node: Support Disable Function - Disable remote access services
main_support_disable() {
    log_info "Starting support disable operation for main node"
    
    # Define support services
    local services=(
        "cloudflared"
        "cockpit"
        "cockpit.socket"
    )
    
    # Check which services need to be disabled
    local services_to_disable=()
    for service in "${services[@]}"; do
        if systemctl is-enabled --quiet "${service}" 2>/dev/null; then
            services_to_disable+=("${service}")
        fi
    done
    
    # Only take action if there are services to disable
    if [ ${#services_to_disable[@]} -eq 0 ]; then
        log_info "All support services are already disabled"
    else
        # Disable and stop all support services that need it
        for service in "${services_to_disable[@]}"; do
        manage_service "${service}" "disable" ""
    done
    fi
    
    log_success "Support disable operation completed for main node"
}

# BACKUP NODE: Support Disable Function - Disable remote access services
backup_support_disable() {
    log_info "Starting support disable operation for backup node"
    
    # Disable and stop support services
    manage_service "cloudflared" "disable" "cloudflare_status"
    manage_service "cockpit" "disable" "cockpit_status"
    manage_service "cockpit.socket" "disable" "cockpit_status"
    
    log_success "Support disable operation completed for backup node"
}

# ============================
# === Process Flag Commands ===
# ============================

# Main node flag processing
process_main_flags() {
    local f1="$1"
    local f2="$2"
    local f3="$3"
    
    # Read current state from the local JSON state file
    local DELETED_FLAG=$(jq -r '.deleted_flag' "${STATE_FILE}")
    local LAST_TRANSITION=$(jq -r '.last_transition' "${STATE_FILE}" 2>/dev/null || echo "")
    local CURRENT_TIME=$(date '+%Y-%m-%dT%H:%M:%S')
    local STATE_CHANGED=false
    
    log_info "Current state: deleted_flag=${DELETED_FLAG}"
    
    # First handle F3 (support mode) as it's independent
    if [ "${f3}" == "true" ]; then
        # Check if any support services are disabled before taking action
        if ! systemctl is-enabled --quiet cloudflared ||
           ! systemctl is-enabled --quiet cockpit ||
           ! systemctl is-enabled --quiet cockpit.socket; then
        # Support Mode (F3 active)
        log_info "F3 active: Enabling remote access"
        main_support
            STATE_CHANGED=true
        else
            log_info "F3 active: Remote access already enabled"
        fi
    else
        # Check if any support services are enabled before taking action
        if systemctl is-enabled --quiet cloudflared 2>/dev/null ||
           systemctl is-enabled --quiet cockpit 2>/dev/null ||
           systemctl is-enabled --quiet cockpit.socket 2>/dev/null; then
        # Support Mode inactive
        log_info "Support mode inactive: Disabling remote access"
        main_support_disable
            STATE_CHANGED=true
        else
            log_info "Support mode inactive: Remote access already disabled"
        fi
    fi
    
    # Then handle F1 (destroy mode)
    if [ "${f1}" == "true" ]; then
        # Destroy Mode (F1 active)
        if sensitive_files_exist || services_running; then
            log_info "F1 active: Files exist or services are running, executing destroy"
            main_destroy
            STATE_CHANGED=true
        fi
        
        # After destroy, check conditions again with detailed logging
        log_info "Checking post-destroy conditions for shutdown..."
        if sensitive_files_exist; then
            log_info "Shutdown blocked: Sensitive files still exist"
        fi
        if services_running; then
            log_info "Shutdown blocked: Services still running"
        fi
        
        if ! sensitive_files_exist && ! services_running; then
            log_info "F1 active: All conditions met for shutdown - files deleted and services stopped"
            update_state "deleted_flag" "yes"
            update_state "last_transition" "${CURRENT_TIME}"
            log_info "Initiating shutdown"
            /usr/sbin/shutdown -h now
            exit 0  # Exit immediately after initiating shutdown
        else
            log_info "F1 active: Shutdown conditions not met - will retry next cycle"
        fi
        # Exit after F1 processing to avoid unnecessary F2 check
        return
    fi
    
    # Finally handle F2 (restore mode) if F1 is not active
    if [ "${f2}" == "true" ]; then
        # Restore Mode (F2 active)
        if [ "${DELETED_FLAG}" == "yes" ] && ! sensitive_files_exist; then
            log_info "F2 active: Files are deleted, restoring them"
            main_restore
            update_state "deleted_flag" "no"
            STATE_CHANGED=true
        else
            log_warn "F2 active: No restore needed - files exist or not in deleted state"
        fi
    fi
    
    # Check if all flags are off and start Tailscale if needed
    if [ "${f1}" != "true" ] && [ "${f2}" != "true" ] && [ "${f3}" != "true" ]; then
        log_info "All flags are off: Ensuring Tailscale is running"
        if ! systemctl is-active --quiet tailscaled; then
            log_info "Starting Tailscale service"
            systemctl start tailscaled
            STATE_CHANGED=true
        fi
    fi
    
    # Only update last_transition if state actually changed
    if [ "$STATE_CHANGED" = true ]; then
        update_state "last_transition" "${CURRENT_TIME}"
        log_info "State changed, updated last_transition timestamp"
    fi
}

# Backup node flag processing
process_backup_flags() {
    local f1="$1"
    local f2="$2"
    local f3="$3"
    
    local CURRENT_TIME=$(date '+%Y-%m-%dT%H:%M:%S')
    local STATE_CHANGED=false
    
    # === F1: Shutdown and disable Syncthing (highest priority) ===
    if [ "${f1}" == "true" ]; then
        log_warn "F1 active: Disabling Syncthing and shutting down."
        backup_destroy
        log_info "Initiating system shutdown"
        /usr/sbin/shutdown -h now
        exit 0  # Exit immediately after initiating shutdown
    fi
    
    # === F3: Enable or Disable Cloudflare and Cockpit (second priority) ===
    if [ "${f3}" == "true" ]; then
        # Check current status before making changes
        local CF_STATUS=$(jq -r '.cloudflare_status' "${STATE_FILE}")
        local CP_STATUS=$(jq -r '.cockpit_status' "${STATE_FILE}")
        
        if [ "${CF_STATUS}" != "on" ] || [ "${CP_STATUS}" != "on" ]; then
        backup_support
            STATE_CHANGED=true
        else
            log_info "F3 active: Support services already enabled"
        fi
    else
        # Check current status before making changes
        local CF_STATUS=$(jq -r '.cloudflare_status' "${STATE_FILE}")
        local CP_STATUS=$(jq -r '.cockpit_status' "${STATE_FILE}")
        
        if [ "${CF_STATUS}" != "off" ] || [ "${CP_STATUS}" != "off" ]; then
        backup_support_disable
            STATE_CHANGED=true
        else
            log_info "F3 inactive: Support services already disabled"
        fi
    fi
    
    # === F2: Start Syncthing if off (third priority) ===
    if [ "${f2}" == "true" ]; then
        local SYNC_STATUS=$(jq -r '.syncthing_status' "${STATE_FILE}")
        if [ "${SYNC_STATUS}" != "on" ]; then
            backup_restore
            log_info "F2 active: Syncthing started."
            STATE_CHANGED=true
        else
            log_info "F2 active: Syncthing already running."
        fi
    fi
    
    # === Check for continuous inactive state (only if no flags are active) ===
    if [ "${f1}" != "true" ] && [ "${f2}" != "true" ] && [ "${f3}" != "true" ]; then
        # Get current time
        local NOW=${CURRENT_TIME}
        
        # Get system startup time
        local SYSTEM_STARTUP=$(jq -r '.system_startup_time' "${STATE_FILE}")
        local SYSTEM_STARTUP_EPOCH=$(date -d "${SYSTEM_STARTUP}" +%s)
        local CURRENT_EPOCH=$(date +%s)
        local UPTIME=$((CURRENT_EPOCH - SYSTEM_STARTUP_EPOCH))
        
        # Update last flags active state
        local LAST_FLAGS_ACTIVE=$(jq -r '.last_flags_active' "${STATE_FILE}")
        if [ "${LAST_FLAGS_ACTIVE}" != "false" ]; then
            update_state "last_flags_active" "false"
            STATE_CHANGED=true
            # Only set continuous_inactive_start if it's not already set
            local CURRENT_INACTIVE_START=$(jq -r '.continuous_inactive_start' "${STATE_FILE}")
            if [ -z "${CURRENT_INACTIVE_START}" ] || [ "${CURRENT_INACTIVE_START}" == "null" ]; then
                update_state "continuous_inactive_start" "${NOW}"
            fi
        fi
        
        # Check continuous inactive time
        local CONTINUOUS_START=$(jq -r '.continuous_inactive_start' "${STATE_FILE}")
        if [ -n "${CONTINUOUS_START}" ] && [ "${CONTINUOUS_START}" != "null" ]; then
            local START_EPOCH=$(date -d "$(echo "${CONTINUOUS_START}" | sed 's/T/ /')" +%s)
            local ELAPSED=$((CURRENT_EPOCH - START_EPOCH))
            
            if [ "${ELAPSED}" -ge 3600 ]; then
                log_info "All flags have been continuously inactive for 1 hour. System uptime: $((UPTIME / 60)) minutes. Shutting down."
                /usr/sbin/shutdown -h now
                exit 0
            else
                log_info "All flags inactive. Continuous inactive time: $((ELAPSED / 60)) minutes. System uptime: $((UPTIME / 60)) minutes."
            fi
        fi
    else
        # Update last flags active state if flags are active
        local LAST_FLAGS_ACTIVE=$(jq -r '.last_flags_active' "${STATE_FILE}")
        if [ "${LAST_FLAGS_ACTIVE}" != "true" ]; then
            update_state "last_flags_active" "true"
            STATE_CHANGED=true
            # Clear continuous_inactive_start when flags become active
            update_state "continuous_inactive_start" ""
        fi
    fi
    
    # Only update last_transition if state actually changed
    if [ "$STATE_CHANGED" = true ]; then
        update_state "last_transition" "${CURRENT_TIME}"
        log_info "State changed, updated last_transition timestamp"
    fi
}

# ============================
# === Script Update Function ===
# ============================
update_script() {
    log_info "Checking for script updates..."
    
    # Get the latest version from GitHub
    local temp_file=$(mktemp)
    if ! curl -fsSL -o "${temp_file}" "${SCRIPT_URL}"; then
        log_error "Failed to download latest script from ${SCRIPT_URL}"
        rm -f "${temp_file}"
        return 1
    fi
    
    # Extract version from downloaded script
    local new_version=$(grep "^# Version:" "${temp_file}" | head -n1 | awk '{print $3}')
    
    if [ -z "${new_version}" ]; then
        log_error "Could not determine version of downloaded script"
        rm -f "${temp_file}"
        return 1
    fi
    
    log_info "Current version: ${CURRENT_VERSION}, Latest version: ${new_version}"
    
    # Compare versions (simple string comparison for now)
    if [ "${new_version}" != "${CURRENT_VERSION}" ]; then
        log_info "New version available. Updating script..."
        
        # Make backup of current script
        cp "${SCRIPT_PATH}" "${SCRIPT_PATH}.bak.$(date +%Y%m%d%H%M%S)"
        
        # Install new version
        cat "${temp_file}" > "${SCRIPT_PATH}"
        chmod +x "${SCRIPT_PATH}"
        
        log_success "Updated script to version ${new_version}"
    else
        log_info "Script is already at the latest version"
    fi
    
    # Clean up
    rm -f "${temp_file}"
    return 0
}

# ============================
# === Command Dispatcher ===
# ============================
dispatch_command() {
    local command="$1"
    local node_type=$(get_node_type)
    
    case "${command}" in
        "monitor")
            log_info "Starting flag monitoring for ${node_type} node"
            init_state
            
            # Fetch flags
            local flags_json
            flags_json=$(fetch_flags) || exit 1
            
            # Parse flags
            local flags
            flags=$(parse_flags "${flags_json}")
            read -r f1 f2 f3 <<< "${flags}"
            
            # Process flags based on node type
            if [ "${node_type}" == "main" ]; then
                process_main_flags "${f1}" "${f2}" "${f3}"
            else
                process_backup_flags "${f1}" "${f2}" "${f3}"
            fi
            ;;
            
        "update")
            update_script
            ;;
            
        "destroy")
            init_state
            if [ "${node_type}" == "main" ]; then
                main_destroy
            else
                backup_destroy
            fi
            ;;
            
        "restore")
            init_state
            if [ "${node_type}" == "main" ]; then
                main_restore
            else
                backup_restore
            fi
            ;;
            
        "support")
            init_state
            if [ "${node_type}" == "main" ]; then
                main_support
            else
                backup_support
            fi
            ;;
            
        "support-disable")
            init_state
            if [ "${node_type}" == "main" ]; then
                main_support_disable
            else
                backup_support_disable
            fi
            ;;
            
        *)
            echo "Usage: $(basename "$0") [monitor|update|destroy|restore|support|support-disable]"
            echo ""
            echo "Commands:"
            echo "  monitor          Check flags and execute appropriate actions"
            echo "  update           Check for and apply script updates"
            echo "  destroy          Execute destroy operation"
            echo "  restore          Execute restore operation"
            echo "  support          Enable remote support access"
            echo "  support-disable  Disable remote support access"
            exit 1
            ;;
    esac
    
    log_info "Execution completed"
}

# ============================
# === Main Execution ===
# ============================
if [ $# -lt 1 ]; then
    echo "Usage: $(basename "$0") [monitor|update|destroy|restore|support|support-disable]"
    exit 1
fi

# Dispatch to appropriate command
dispatch_command "$1" 