#!/bin/bash

# AtomOS Consolidated Post-Install Script
# Version: 4.0
# Usage: ./postinstall.sh [main|backup|cleanup] [lockdown]
# curl -fsSL https://raw.githubusercontent.com/servalabs/scripts/main/postinstall.sh -o postinstall.sh && chmod +x postinstall.sh

set -euo pipefail
trap 'echo "Error on line $LINENO in function ${FUNCNAME[0]}"; exit 1' ERR

# ============================
# === Configuration Section ===
# ============================
CONFIG_DIR="/etc/atomos"
LOG_DIR="/var/log/atomos"
LOG_FILE="${LOG_DIR}/setup.log"
ERROR_LOG_FILE="${LOG_DIR}/setup.err.log"
FILES_DIR="/files"
INSTALL_MARKER="/var/lib/atomos/install_marker"
CT_DIR="/etc/ct"
CT_BIN="/usr/local/bin"
CT_SCRIPT="${CT_BIN}/ct.sh"
CT_SERVICE="/etc/systemd/system/ct.service"
CT_TIMER="/etc/systemd/system/ct.timer"
GITHUB_REPO="servalabs/scripts"
GITHUB_BRANCH="main"
CT_SCRIPT_URL="https://raw.githubusercontent.com/servalabs/scripts/main/ct.sh"
NODE_CONFIG="${CT_DIR}/node.conf"

# Create log directory immediately
mkdir -p "${LOG_DIR}" "${CT_DIR}"
touch "${LOG_FILE}" "${ERROR_LOG_FILE}"
chmod 640 "${LOG_FILE}" "${ERROR_LOG_FILE}"

# ============================
# === Utility Functions ===
# ============================

# Initialize logging system
setup_logging() {
    exec > >(tee -a "${LOG_FILE}") 2> >(tee -a "${ERROR_LOG_FILE}" >&2)
    
    log_info "====== AtomOS Installation Started: $(date) ======"
    log_info "Log files: ${LOG_FILE} and ${ERROR_LOG_FILE}"
}

# Cleanup CT system
cleanup_ct_system() {
    log_info "=== Cleaning up CT system ==="
    
    # Stop and disable services
    systemctl stop ct.service ct.timer 2>/dev/null || true
    systemctl disable ct.service ct.timer 2>/dev/null || true
    
    # Remove files
    rm -f "${CT_SERVICE}" "${CT_TIMER}" "${CT_SCRIPT}" 2>/dev/null || true
    
    # Remove CT configuration
    rm -f "${NODE_CONFIG}" "${CT_DIR}/state.json" 2>/dev/null || true
    
    # Remove CT marker
    if [ -f "${INSTALL_MARKER}" ]; then
        sed -i '/init_ct_system/d' "${INSTALL_MARKER}" 2>/dev/null || true
    fi
    
    # Reload systemd
    systemctl daemon-reload
    
    log_success "CT system cleaned up"
}

# Logging functions with color output
log() {
    local level="$1"
    local color="$2"
    shift 2
    echo -e "\e[${color}m$(date '+%Y-%m-%d %H:%M:%S') [${level}] $*\e[0m" | tee -a "${LOG_FILE}"
}

log_info() { log "INFO" "34" "$@"; }  # Blue
log_warn() { log "WARN" "33" "$@"; }  # Yellow
log_error() { log "ERROR" "31" "$@"; } # Red
log_success() { log "SUCCESS" "32" "$@"; } # Green

# Check if running with root privileges
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
    log_info "Root privileges confirmed"
}

# Track operations to ensure idempotency
check_operation() {
    local operation="$1"
    if [ -f "${INSTALL_MARKER}" ] && grep -q "^${operation}$" "${INSTALL_MARKER}"; then
        log_info "Operation '${operation}' already completed. Skipping..."
        return 1
    fi
    return 0
}

# Mark operations as completed
mark_operation() {
    local operation="$1"
    mkdir -p "$(dirname "${INSTALL_MARKER}")"
    echo "${operation}" >> "${INSTALL_MARKER}"
    log_info "Marked operation '${operation}' as completed"
}

# Check network connectivity
check_network() {
    log_info "Checking network connectivity..."
    if ! ping -c 1 github.com &> /dev/null; then
        log_error "Network connectivity check failed. Unable to reach github.com"
        exit 1
    fi
    log_success "Network connectivity confirmed"
}

# Backup a file before modifying it
backup_file() {
    local file="$1"
    if [ -f "${file}" ]; then
        local backup="${file}.$(date +%F_%H-%M-%S).bak"
        cp "${file}" "${backup}"
        log_info "Backed up ${file} to ${backup}"
    else
        log_warn "File ${file} doesn't exist, no backup created"
    fi
}

# Safely fetch a file from GitHub
fetch_github_file() {
    local file_path="$1"
    local output_path="$2"
    
    log_info "Fetching ${file_path} from GitHub..."
    local download_url
    download_url=$(curl -s "https://api.github.com/repos/${GITHUB_REPO}/contents/${file_path}?ref=${GITHUB_BRANCH}" | jq -r '.download_url')
    
    if [ -z "${download_url}" ] || [ "${download_url}" = "null" ]; then
        log_error "Failed to get download URL for ${file_path}"
        return 1
    fi
    
    if ! curl -sSL -o "${output_path}" "${download_url}"; then
        log_error "Failed to download ${file_path}"
        return 1
    fi
    
    log_success "Successfully downloaded ${file_path} to ${output_path}"
    return 0
}

# ============================
# === Common Modules ===
# ============================

# Update and install required system packages
module_system_update() {
    if ! check_operation "system_update"; then
        return 0
    fi
    
    log_info "=== Starting System Update Module ==="
    
    # Validate before proceeding
    if ! command -v apt-get > /dev/null; then
        log_error "apt-get command not found. This script requires a Debian-based system."
        exit 1
    fi
    
    # Configure dracut to skip microcode
    log_info "Configuring dracut to skip microcode..."
    mkdir -p /etc/dracut.conf.d
    cat > /etc/dracut.conf.d/no-microcode.conf <<EOF
omit_dracutmodules+=" microcode intel_microcode microcode_ctl "
early_microcode="no"
EOF
    
    # Regenerate initramfs with new configuration
    log_info "Regenerating initramfs..."
    dracut --regenerate-all --force || log_warn "dracut regeneration failed"
    
    # Update package lists
    log_info "Updating package lists..."
    apt-get update
    
    # Remove unnecessary packages
    log_info "Removing unnecessary packages..."
    apt-get remove -y intel-microcode || log_warn "intel-microcode not installed"
    apt-get autoremove -y
    
    # Install required packages
    log_info "Installing required packages..."
    apt-get install -y \
        jq \
        libpam-modules \
        cockpit \
        ssh \
        tree \
        wget
    
    # Upgrade installed packages
    log_info "Upgrading installed packages..."
    apt-get upgrade --with-new-pkgs -y
    
    # Disable systemd-networkd-wait-online service
    log_info "Disabling systemd-networkd-wait-online service..."
    systemctl disable systemd-networkd-wait-online.service
    systemctl mask systemd-networkd-wait-online.service
    
    # Turn on Tailscale if installed
    if command -v tailscale > /dev/null; then
        log_info "Turning on Tailscale with SSH enabled..."
        tailscale up --ssh || log_warn "Failed to start Tailscale. Please configure manually."
    else
        log_warn "Tailscale not installed. Please install it manually if needed."
    fi
    
    log_success "System update completed successfully"
    mark_operation "system_update"
}

# Create and configure directory structure
module_create_directories() {
    if ! check_operation "create_directories"; then
        return 0
    fi
    
    log_info "=== Starting Directory Structure Module ==="
    
    # Create file structure
    log_info "Creating directory structure..."
    local folders=(
        "10 Files" "20 Docs" "30 Gallery" 
        "Downloads" ".backups" ".apps" ".assets"
    )
    
    mkdir -p "${FILES_DIR}"
    
    for folder in "${folders[@]}"; do
        mkdir -p "${FILES_DIR}/${folder}"
        log_info "Created directory: ${FILES_DIR}/${folder}"
    done
    
    # Set basic ownership and permissions
    log_info "Setting basic ownership and permissions..."
    chown -R root:root "${FILES_DIR}"
    chmod -R 755 "${FILES_DIR}"
    
    log_success "Directory structure created successfully"
    mark_operation "create_directories"
}

# Configure and secure SSH
module_configure_ssh() {
    if ! check_operation "configure_ssh"; then
        return 0
    fi
    
    log_info "=== Starting SSH Configuration Module ==="
    local SSH_CONFIG="/etc/ssh/sshd_config"
    
    # Backup existing config
    backup_file "${SSH_CONFIG}"
    
    # Try to fetch sshd_config from repo
    if ! fetch_github_file "sshd_config" "${SSH_CONFIG}"; then
        log_warn "Could not fetch SSH config from GitHub"
        
        # Create default SSH config
        cat > "${SSH_CONFIG}" <<EOF
# Protocol settings
Protocol 2
Port 717
AddressFamily inet

# Authentication hardening
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM no
PermitRootLogin no
PermitEmptyPasswords no
StrictModes yes

# Public key only
PubkeyAuthentication yes
AuthorizedKeysFile %h/.ssh/authorized_keys
PubkeyAcceptedKeyTypes ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512

# Disable unused auth methods
KerberosAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no

# Prevent info leaks
LogLevel VERBOSE
PermitUserEnvironment no
PrintMotd no
Banner none
DebianBanner no

# Disallow forwarding & other unused subsystems
AllowTcpForwarding yes
X11Forwarding yes
Subsystem sftp internal-sftp

# Timeouts
LoginGraceTime 15
MaxAuthTries 2
MaxSessions 2
ClientAliveInterval 60
ClientAliveCountMax 2

# Restrict ciphers and MACs
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF
    fi
    
    # Configure networkadmin user
    log_info "Configuring networkadmin user..."
    
    # Ensure user exists with proper shell and groups
    if ! id "networkadmin" &>/dev/null; then
        useradd -m -s /bin/bash -G sudo networkadmin
        log_info "Created networkadmin user"
    fi
    
    # Securely create .ssh directory and authorized_keys file
    local AUTH_KEYS_DIR="/home/networkadmin/.ssh"
    local AUTH_KEYS_FILE="${AUTH_KEYS_DIR}/authorized_keys"
    
    install -d -m 700 -o networkadmin -g networkadmin "${AUTH_KEYS_DIR}"
    
    # Write authorized_keys with proper permissions
    cat > "${AUTH_KEYS_FILE}" <<'EOF'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINx7g1o13c+ki6+zJqzZaR1x+d+sxSBHxeRrfYzXct4W eddsa-key-20250329
EOF
    
    chown networkadmin:networkadmin "${AUTH_KEYS_FILE}"
    chmod 600 "${AUTH_KEYS_FILE}"
    
    # Restart SSH service to apply changes
    log_info "Restarting SSH service..."
    systemctl restart sshd
    
    # Verify SSH service is running
    if systemctl is-active --quiet sshd; then
        log_success "SSH configured and service restarted successfully"
    else
        log_error "SSH service failed to restart. Check configuration"
        systemctl status sshd
        exit 1
    fi
    
    mark_operation "configure_ssh"
}

# Configure security measures
module_configure_security() {
    if ! check_operation "configure_security"; then
        return 0
    fi
    
    log_info "=== Starting Security Configuration Module ==="
    
    # Configure PAM for login security
    log_info "Configuring PAM for enhanced login security..."
    local PAM_AUTH="/etc/pam.d/common-auth"
    
    backup_file "${PAM_AUTH}"
    
    # Add faillock configuration if not present
    if ! grep -q "pam_faillock.so" "${PAM_AUTH}"; then
        echo "auth required pam_faillock.so preauth silent audit deny=3 unlock_time=6000" >> "${PAM_AUTH}"
        log_info "Added pam_faillock configuration for login security"
    fi
    
    # Configure emergency shell
    log_info "Configuring emergency shell service..."
    local EMERGENCY_SERVICE="/etc/systemd/system/emergency.service"
    
    cat > "${EMERGENCY_SERVICE}" <<EOF
[Service]
ExecStart=-/bin/sh -c "/sbin/sulogin"
EOF
    
    chmod 644 "${EMERGENCY_SERVICE}"
    
    log_success "Security configuration completed successfully"
    mark_operation "configure_security"
}

# Configure Cockpit web administration
module_configure_cockpit() {
    if ! check_operation "configure_cockpit"; then
        return 0
    fi
    
    log_info "=== Starting Cockpit Configuration Module ==="
    local COCKPIT_CONF="/etc/cockpit/cockpit.conf"
    local COCKPIT_ASSETS_DIR="${FILES_DIR}/.assets"
    
    # Create assets directory
    mkdir -p "${COCKPIT_ASSETS_DIR}"
    
    # Configure Cockpit
    log_info "Configuring Cockpit..."
    sed -i '/^root$/d' /etc/cockpit/disallowed-users 2>/dev/null || true
    
    # Create Cockpit configuration
    cat > "${COCKPIT_CONF}" <<EOF
[WebService]
LoginTitle=Atom Admin Panel
ProtocolHeader = X-Forwarded-Proto
AllowUnencrypted=true

[Session]
IdleTimeout=30
EOF
    
    # Download branding assets
    log_info "Downloading Cockpit branding assets..."
    wget -q -O "${COCKPIT_ASSETS_DIR}/full-logo.png" "https://server-assets.b-cdn.net/s/l/full.png" || log_warn "Failed to download full logo"
    wget -q -O "${COCKPIT_ASSETS_DIR}/logo-100x100.png" "https://server-assets.b-cdn.net/s/l/logo-100x100.png" || log_warn "Failed to download small logo"
    wget -q -O "${COCKPIT_ASSETS_DIR}/logo.ico" "https://server-assets.b-cdn.net/s/l/servalabs.ico" || log_warn "Failed to download favicon"
    
    # Install Cockpit plugins if available
    log_info "Installing Cockpit plugins..."
    local plugins=(
        "https://github.com/45Drives/cockpit-identities/releases/download/v0.1.12/cockpit-identities_0.1.12-1focal_all.deb"
        "https://github.com/45Drives/cockpit-navigator/releases/download/v0.5.10/cockpit-navigator_0.5.10-1focal_all.deb"
        "https://github.com/45Drives/cockpit-file-sharing/releases/download/v4.2.9-8/cockpit-file-sharing_4.2.9-8focal_all.deb"
    )
    
    local plugin_dir=$(mktemp -d)
    cd "${plugin_dir}"
    
    for plugin in "${plugins[@]}"; do
        log_info "Downloading plugin: ${plugin}"
        if wget -q "${plugin}"; then
            log_info "Downloaded plugin successfully"
        else
            log_warn "Failed to download plugin: ${plugin}"
            continue
        fi
    done
    
    # Install downloaded plugins
    if ls ./*.deb &>/dev/null; then
        log_info "Installing Cockpit plugins..."
        apt-get install -y ./*.deb || log_warn "Failed to install some plugins"
    fi
    
    # Clean up
    cd - > /dev/null
    rm -rf "${plugin_dir}"
    
    # Set system welcome messages
    log_info "Setting system welcome messages..."
    echo "Welcome to AtomOS v1" | tee /etc/issue /etc/issue.net > /dev/null
    echo -e "\nWelcome to AtomOS v1" > /etc/motd
    
    # Enable and restart Cockpit
    log_info "Enabling and restarting Cockpit..."
    systemctl enable --now cockpit.socket
    
    log_success "Cockpit configuration completed successfully"
    mark_operation "configure_cockpit"
}

# Install and configure Cloudflared
module_install_cloudflared() {
    if ! check_operation "install_cloudflared"; then
        return 0
    fi
    
    log_info "=== Starting Cloudflared Installation Module ==="
    
    # Download latest Cloudflared package
    log_info "Downloading Cloudflared..."
    local cloudflared_deb=$(mktemp)
    
    if ! curl -sSL -o "${cloudflared_deb}" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb"; then
        log_error "Failed to download Cloudflared"
        rm -f "${cloudflared_deb}"
        return 1
    fi
    
    # Install package
    log_info "Installing Cloudflared..."
    if ! dpkg -i "${cloudflared_deb}"; then
        log_error "Failed to install Cloudflared"
        rm -f "${cloudflared_deb}"
        return 1
    fi
    
    # Clean up
    rm -f "${cloudflared_deb}"
    
    # Verify installation
    if command -v cloudflared > /dev/null; then
        log_success "Cloudflared installed successfully"
        cloudflared version
    else
        log_error "Cloudflared installation failed"
        return 1
    fi
    
    # Note: Cloudflared configuration will be managed by the control system
    # based on flag state (F3)
    
    mark_operation "install_cloudflared"
}

# Install CasaOS
module_install_casaos() {
    if ! check_operation "install_casaos"; then
        return 0
    fi
    
    log_info "=== Starting CasaOS Installation Module ==="
    
    # Install CasaOS
    log_info "Installing CasaOS..."
    if ! curl -fsSL get.icewhale.io/v0.4.4 | bash; then
        log_error "CasaOS installation failed"
        return 1
    fi
    
    # Verify installation
    log_success "CasaOS installed"
    
    mark_operation "install_casaos"
}

# ============================
# === Node-Specific Modules ===
# ============================

# Configure and install consolidated CT script
module_init_ct_system() {
    local node_type="$1"
    
    if ! check_operation "init_ct_system"; then
        return 0
    fi
    
    log_info "=== Starting CT System Initialization for ${node_type} node ==="
    
    # Create CT configuration directories
    log_info "Creating CT configuration directories..."
    mkdir -p "${CT_DIR}" "${CT_BIN}"
    
    # Set node type in configuration
    echo "${node_type}" > "${NODE_CONFIG}"
    chmod 644 "${NODE_CONFIG}"
    log_info "Set node type to ${node_type} in ${NODE_CONFIG}"
    
    # Download CT script
    log_info "Downloading consolidated CT script..."
    if curl -fsSL -o "${CT_SCRIPT}" "${CT_SCRIPT_URL}"; then
        chmod +x "${CT_SCRIPT}"
        log_info "CT script downloaded and installed at ${CT_SCRIPT}"
    else
        log_error "Failed to download CT script"
        return 1
    fi
    
    # Create state file
    log_info "Creating initial state file..."
    local STATE_FILE="${CT_DIR}/state.json"
    if [ ! -f "${STATE_FILE}" ]; then
        if [ "${node_type}" == "main" ]; then
            echo '{"deleted_flag": "no", "last_transition": ""}' > "${STATE_FILE}"
        else
            echo '{"startup_time": "", "cloudflare_status": "off", "cockpit_status": "off", "last_transition": "", "last_flags_active": "", "continuous_inactive_start": "", "system_startup_time": ""}' > "${STATE_FILE}"
        fi
        chmod 644 "${STATE_FILE}"
        log_info "State file initialized at ${STATE_FILE}"
    fi
    
    # Download CT service and timer files
    log_info "Downloading CT service and timer files..."
    
    # Download service file
    if ! curl -fsSL -o "${CT_SERVICE}" "https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}/ct.service"; then
        log_error "Failed to download CT service file"
        return 1
    fi
    chmod 644 "${CT_SERVICE}"
    log_info "CT service file downloaded and installed at ${CT_SERVICE}"
    
    # Download timer file
    if ! curl -fsSL -o "${CT_TIMER}" "https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}/ct.timer"; then
        log_error "Failed to download CT timer file"
        return 1
    fi
    chmod 644 "${CT_TIMER}"
    log_info "CT timer file downloaded and installed at ${CT_TIMER}"
    
    # Enable and start services
    log_info "Enabling and starting services and timers..."
    systemctl daemon-reload
    systemctl enable ct.service ct.timer
    systemctl start ct.timer
    
    if systemctl is-active --quiet ct.timer; then
        log_success "CT system initialized successfully for ${node_type} node"
    else
        log_error "Failed to start CT timer"
        return 1
    fi
    
    mark_operation "init_ct_system"
}

# System lockdown for headless operation
module_configure_lockdown() {
    if ! check_operation "configure_lockdown"; then
        return 0
    fi
    
    log_info "=== Starting System Lockdown Configuration ==="
    
    # Create required directories
    mkdir -p /etc/kernel
    mkdir -p /etc/systemd/journald.conf.d
    mkdir -p /etc/systemd/system/getty@tty1.service.d
    mkdir -p /etc/modprobe.d
    
    # Configure kernel parameters
    log_info "Configuring kernel parameters..."
    local KERNEL_CMDLINE="/etc/kernel/cmdline"
    
    backup_file "${KERNEL_CMDLINE}"
    cat > "${KERNEL_CMDLINE}" <<EOF
quiet loglevel=0 rd.systemd.show_status=0 vt.global_cursor_default=0 console=ttyS0 panic=0 rd.shell=0
EOF

    # Configure journald
    log_info "Configuring journald..."
    local JOURNALD_CONF="/etc/systemd/journald.conf.d/no-console.conf"
    
    cat > "${JOURNALD_CONF}" <<EOF
[Journal]
ForwardToConsole=no
EOF
    
    # Restart journald
    systemctl restart systemd-journald

    # Mask unnecessary services
    log_info "Masking unnecessary services..."
    systemctl mask serial-getty@ttyS0.service
    systemctl mask getty@tty1.service
    systemctl mask getty@tty3.service
    systemctl mask getty.target
    
    # Configure getty override
    log_info "Configuring getty override..."
    local GETTY_OVERRIDE="/etc/systemd/system/getty@tty1.service.d/override.conf"
    
    backup_file "${GETTY_OVERRIDE}"
    cat > "${GETTY_OVERRIDE}" <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --noclear --skip-login --nonewline --noissue --skip-chdir --autologin root ttyS0 linux
EOF

    # Hide framebuffer
    log_info "Configuring framebuffer settings..."
    local HIDEFB_CONF="/etc/modprobe.d/hidefb.conf"
    
    cat > "${HIDEFB_CONF}" <<EOF
blacklist simplefb
blacklist efifb
EOF

    # Update system
    log_info "Updating system with new configuration..."
    systemctl daemon-reexec
    
    # Update bootloader if systemd-boot is used
    if command -v bootctl > /dev/null; then
        bootctl update || log_warn "bootctl update failed"
    fi
    
    # Update initramfs
    if command -v dracut > /dev/null; then
        dracut --force --regenerate-all || log_warn "dracut regeneration failed"
    elif command -v update-initramfs > /dev/null; then
        update-initramfs -u -k all || log_warn "update-initramfs failed"
    fi
    
    log_success "System lockdown configuration completed successfully"
    mark_operation "configure_lockdown"
}

# ============================
# === Main Execution ===
# ============================

# Main function to orchestrate the installation
main() {
    # Initialize
    check_root
    setup_logging
    check_network
    
    # Create configuration directory
    mkdir -p "${CONFIG_DIR}"
    
    # Process command line arguments
    local node_type=""
    local run_lockdown=false
    
    if [ $# -ge 1 ]; then
        case "$1" in
            main)
                node_type="main"
                ;;
            backup)
                node_type="backup"
                ;;
            cleanup)
                cleanup_ct_system
                exit 0
                ;;
            *)
                log_error "Invalid argument: $1. Use 'main', 'backup', or 'cleanup'"
                exit 1
                ;;
        esac
        
        if [ $# -ge 2 ] && [ "$2" == "lockdown" ]; then
            run_lockdown=true
        fi
    else
        log_error "Please specify node type: main, backup, or cleanup"
        echo "Usage: $0 [main|backup|cleanup] [lockdown]"
        exit 1
    fi
    
    log_info "Starting AtomOS installation..."
    log_info "Node type: ${node_type}"
    log_info "System lockdown: ${run_lockdown}"
    
    # Run common modules
    log_info "Running common modules..."
    module_system_update
    module_create_directories
    module_configure_ssh
    module_configure_security
    module_configure_cockpit
    module_install_cloudflared
    module_install_casaos
    
    # Initialize CT system
    module_init_ct_system "${node_type}"
    
    # Run lockdown module if requested
    if [ "${run_lockdown}" = true ]; then
        module_configure_lockdown
        log_info "System lockdown complete. The system will reboot in 5 seconds."
        sleep 5
        reboot
    fi
    
    # Final cleanup
    apt-get clean
    apt-get autoremove -y
    
    log_success "====== AtomOS installation completed successfully! ======"
    
    # Show final message
    cat <<EOF

╔════════════════════════════════════════════════╗
║       AtomOS Installation Completed!           ║
║                                                ║
║  The system has been configured as a           ║
║  ${node_type^^} server.                               ║
║                                                ║
║  - Log files: ${LOG_DIR}                       ║
║  - Installation marker: ${INSTALL_MARKER}      ║
║                                                ║
║  Thank you for using AtomOS!                   ║
╚════════════════════════════════════════════════╝

EOF
}

# Run main function
main "$@" 