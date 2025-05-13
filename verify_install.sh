#!/bin/bash

# curl -fsSL "https://raw.githubusercontent.com/servalabs/scripts/$(curl -s https://api.github.com/repos/servalabs/scripts/commits?path=verify_install.sh\&per_page=1 | jq -r '.[0].sha')/verify_install.sh" -o verify_install.sh && chmod +x verify_install.sh && ./verify_install.sh

echo "AtomOS Installation Verify Script v1.1"
sleep 2

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration paths
CONFIG_DIR="/etc/atomos"
LOG_DIR="/var/log/atomos"
CT_DIR="/etc/ct"
CT_BIN="/usr/local/bin"
CT_SCRIPT="${CT_BIN}/ct.sh"
FILES_DIR="/files"

# Function to print status
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "true" ] || [ "$status" = true ]; then
        echo -e "${GREEN}✓${NC} $message"
    else
        echo -e "${RED}✗${NC} $message"
    fi
}

# Function to check if a service is running
check_service() {
    local service=$1
    if systemctl is-active --quiet "$service"; then
        echo "true"
    else
        echo "false"
    fi
}

# Function to check if a file exists and has correct permissions
check_file() {
    local file=$1
    local expected_perms=$2
    if [ -f "$file" ]; then
        local actual_perms=$(stat -c "%a" "$file")
        if [ "$actual_perms" = "$expected_perms" ]; then
            echo "true"
        else
            echo "false"
        fi
    else
        echo "false"
    fi
}

# Function to check if a directory exists
check_dir() {
    local dir=$1
    if [ -d "$dir" ]; then
        echo "true"
    else
        echo "false"
    fi
}

# Function to check if a package is installed
check_package() {
    local package=$1
    if dpkg -l | grep -q "^ii  $package "; then
        echo "true"
    else
        echo "false"
    fi
}

# Function to check if Cockpit is properly installed
check_cockpit() {
    if dpkg -l | grep -q "^ii  cockpit "; then
        echo "true"
    else
        echo "false"
    fi
}

echo "Starting AtomOS installation verification..."
echo "=========================================="

# Check root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

# Check required directories
echo -e "\nChecking required directories..."
print_status "$(check_dir "$CONFIG_DIR")" "Configuration directory exists"
print_status "$(check_dir "$LOG_DIR")" "Log directory exists"
print_status "$(check_dir "$CT_DIR")" "CT directory exists"
print_status "$(check_dir "$FILES_DIR")" "Files directory exists"

# Check required files
echo -e "\nChecking required files..."
print_status "$(check_file "$CT_SCRIPT" "755")" "CT script exists"
print_status "$(check_file "${CT_DIR}/node.conf" "644")" "Node configuration exists"
print_status "$(check_file "${CT_DIR}/state.json" "644")" "State file exists"

# Check services
echo -e "\nChecking services..."
print_status "$(check_service "cockpit.socket")" "Cockpit service is running"
print_status "$(check_service "ct.timer")" "CT timer is running"
print_status "$(check_service "ct-update.timer")" "CT update timer is running"

# Check installed packages
echo -e "\nChecking installed packages..."
print_status "$(command -v jq >/dev/null 2>&1 && echo "true" || echo "false")" "jq is installed"
print_status "$(check_cockpit)" "Cockpit is installed"
print_status "$(command -v cloudflared >/dev/null 2>&1 && echo "true" || echo "false")" "Cloudflared is installed"
print_status "$(command -v casaos >/dev/null 2>&1 && echo "true" || echo "false")" "CasaOS is installed"

# Check SSH configuration
echo -e "\nChecking SSH configuration..."
print_status "$(check_file "/etc/ssh/sshd_config" "644")" "SSH config exists"
print_status "$(check_service "sshd")" "SSH service is running"
print_status "$(check_dir "/home/networkadmin/.ssh")" "networkadmin SSH directory exists"
print_status "$(check_file "/home/networkadmin/.ssh/authorized_keys" "600")" "networkadmin authorized_keys exists"

# Check file permissions
echo -e "\nChecking file permissions..."
print_status "$(check_file "$CT_SCRIPT" "755")" "CT script has correct permissions"
print_status "$(check_file "${CT_DIR}/node.conf" "644")" "Node config has correct permissions"
print_status "$(check_file "${CT_DIR}/state.json" "644")" "State file has correct permissions"

# Check systemd services
echo -e "\nChecking systemd services..."
print_status "$(check_file "/etc/systemd/system/ct.service" "644")" "CT service file exists"
print_status "$(check_file "/etc/systemd/system/ct.timer" "644")" "CT timer file exists"
print_status "$(check_file "/etc/systemd/system/ct-update.service" "644")" "CT update service file exists"
print_status "$(check_file "/etc/systemd/system/ct-update.timer" "644")" "CT update timer file exists"

# Check if node type is set
echo -e "\nChecking node configuration..."
if [ -f "${CT_DIR}/node.conf" ]; then
    NODE_TYPE=$(cat "${CT_DIR}/node.conf")
    echo -e "${GREEN}Node type: ${NODE_TYPE}${NC}"
else
    echo -e "${RED}Node type not configured${NC}"
fi

echo -e "\nVerification complete!"
echo "==========================================" 