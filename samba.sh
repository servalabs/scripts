#!/bin/bash
# samba.sh Samba Share Configuration Script

set -euo pipefail

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  -u, --user USERNAME     Samba username"
    echo "  -p, --password PASS     Samba password"
    echo "  -s, --share SHARE_NAME  Share name (default: files)"
    echo "  -h, --help              Display this help message"
    exit 1
}

# Parse command line arguments
smb_user=""
smb_pass=""
share_name="files"

while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--user)
            smb_user="$2"
            shift 2
            ;;
        -p|--password)
            smb_pass="$2"
            shift 2
            ;;
        -s|--share)
            share_name="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Ensure the script is run as root.
if [ "$EUID" -ne 0 ]; then
  echo "❌ This script must be run as root. Aborting."
  exit 1
fi

# Variables
samba_conf="/etc/samba/smb.conf"
samba_dir="/files"
smbusers_file="/etc/samba/smbusers"

# If username not provided via arguments, prompt for it
if [ -z "$smb_user" ]; then
    read -p "Enter the Share username (e.g., admin): " smb_user
fi

# If password not provided via arguments, prompt for it
if [ -z "$smb_pass" ]; then
    while true; do
        read -s -p "Enter the Share password: " smb_pass
        echo
        read -s -p "Confirm the Share password: " smb_pass_confirm
        echo
        if [ "$smb_pass" != "$smb_pass_confirm" ]; then
            echo "❌ Passwords do not match. Please try again."
        elif [ -z "$smb_pass" ]; then
            echo "❌ Password cannot be empty. Please try again."
        else
            break
        fi
    done
fi

# Ensure the Samba configuration file exists.
if [ ! -f "$samba_conf" ]; then
  echo "❌ Share configuration file not found at $samba_conf. Aborting."
  exit 1
fi

# Ensure the Samba directory exists.
if [ ! -d "$samba_dir" ]; then
  echo "📁 Directory $samba_dir does not exist. Creating it..."
  mkdir -p "$samba_dir"
fi

# Backup the original smb.conf with a timestamp.
backup_file="${samba_conf}.$(date +%F_%H-%M-%S).bak"
cp "$samba_conf" "$backup_file"
echo "📦 Backup of Share configuration saved to $backup_file"

# Remove any existing share block with the same name.
# This awk command deletes a section that starts with the share name.
awk -v share="[$share_name]" '
  BEGIN { skip=0 }
  /^\[.*\]/ {
    if ($0 == share) { skip=1 } else { skip=0 }
  }
  { if (!skip) print $0 }
' "$backup_file" > "$samba_conf"

# Ensure the username map is enabled in the [global] section.
if ! grep -q "^ *username map *= *$smbusers_file" "$samba_conf"; then
  sed -i '/^\[global\]/a username map = '"$smbusers_file" "$samba_conf"
fi

# Append new share block.
cat >> "$samba_conf" <<EOL

[$share_name]
   path = $samba_dir
   read only = no
   browsable = yes
   guest ok = no
   writable = yes
   valid users = $smb_user
   create mask = 0770
   directory mask = 0770
EOL

echo "🔧 Added new Share [$share_name] to $samba_conf"

# Create system user if it doesn't exist.
if ! id -u "$smb_user" >/dev/null 2>&1; then
  useradd -M -s /usr/sbin/nologin "$smb_user"
  echo "👤 Created system user '$smb_user'."
fi

# Create docker group if it doesn't exist and add user to it
if ! getent group docker >/dev/null 2>&1; then
  groupadd docker
  echo "👥 Created docker group."
fi
usermod -aG docker "$smb_user"
echo "🐳 Added '$smb_user' to necessary group."

# Update the Samba users mapping.
if [ ! -f "$smbusers_file" ]; then
  touch "$smbusers_file"
fi

tmp_smbusers=$(mktemp)
grep -v "^$smb_user =" "$smbusers_file" 2>/dev/null > "$tmp_smbusers" || true
echo "$smb_user = $smb_user" >> "$tmp_smbusers"
mv "$tmp_smbusers" "$smbusers_file"
echo "🔄 Updated Share users mapping in $smbusers_file."

# Add user to Samba.
if command -v smbpasswd >/dev/null 2>&1; then
  ( echo "$smb_pass"; echo "$smb_pass" ) | smbpasswd -a -s "$smb_user"
  echo "🔑 Added '$smb_user' to Share with the provided password."
else
  echo "❌ smbpasswd command not found. Please install Samba and try again."
  exit 1
fi

# Restart Samba services if they are active.
if systemctl is-active --quiet smbd; then
  systemctl restart smbd
  echo "🔄 Restarted smbd service."
fi

if systemctl is-active --quiet nmbd; then
  systemctl restart nmbd
  echo "🔄 Restarted nmbd service."
fi

echo "✅ Share [$share_name] created at $samba_dir, accessible to user '$smb_user'."
