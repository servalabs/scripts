#!/bin/bash
set -euo pipefail

# === Trap errors and print failing line ===
trap 'echo -e "\n⚠️  Error on line $LINENO. Check logs for details." >&2' ERR

# === Script metadata ===
# This script audits key areas of a Debian 12+ system using systemd and dracut.
# It checks for users, services, cron jobs, suspicious binaries, and much more.
# Output is logged to /var/log/system_audit_<timestamp>.log

export DEBIAN_FRONTEND=noninteractive

# === Ensure root privileges ===
if [[ "$(id -u)" -ne 0 ]]; then
    echo "❌ Please run as root."
    exit 1
fi

# === Parse options ===
VERBOSE=1
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
HOSTNAME=$(hostname -s)
LOG_FILE="/var/log/system_audit_${HOSTNAME}_${TIMESTAMP}.log"
ERR_LOG="${LOG_FILE%.log}.err.log"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --report)
            shift
            [[ -n "${1-}" ]] && LOG_FILE="$1" || { echo "Error: --report requires path"; exit 1; }
            ERR_LOG="${LOG_FILE%.log}.err.log"
            shift
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        --quiet)
            VERBOSE=0
            shift
            ;;
        --help|-h)
            echo "Usage: sudo $0 [--report /path/to/file] [--verbose|--quiet] [--help]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# === Prepare logging ===
touch "$LOG_FILE" || { echo "❌ Cannot write to $LOG_FILE"; exit 1; }
exec > >(tee -a "$LOG_FILE") \
     2> >(tee -a "$ERR_LOG" >&2)

echo -e "🛡️  System Audit Started: $(date)"
echo "📄 Log file: $LOG_FILE"
echo "⚠️  Error log: $ERR_LOG"

# === Logging helpers ===
log() {
    [[ $VERBOSE -eq 1 ]] && echo -e "$1"
    echo -e "$1"
}

highlight() {
    log "\n\033[1;31m$1\033[0m"
}

section() {
    highlight "=== $1 ==="
}

# === Begin audit sections ===

section "Users and Root Access"
log "Logged-in user: $USER"
log "Users with valid login shells:"
getent passwd | grep -Ev '(/false|/nologin)'
for grp in sudo wheel; do
    log "Users in '$grp' group:"
    getent group "$grp" || log "(Group '$grp' not found)"
done

section "SUID/SGID Binaries (Potential Escalation)"
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null

section "Network Services Listening (Non-loopback)"
ss -tulnp | grep -vE '127.0.0.1|::1' || log "No external listeners found."

section "Startup Services (Systemd)"
systemctl list-unit-files --type=service --state=enabled

section "Cron Jobs"
if crontab -l &>/dev/null; then
    log "Current user's crontab:"
    crontab -l
fi
for user in $(cut -f1 -d: /etc/passwd); do
    if crontab -u "$user" -l &>/dev/null; then
        log "Crontab for user: $user"
        crontab -u "$user" -l
    fi
done
log "System-wide cron files:"
find /etc/cron* -type f -exec ls -l {} \; 2>/dev/null

section "Suspicious Scripts or Commands"
grep -rE --color=never 'curl|wget|base64|eval|nc|python -c|bash -i' /etc /home /opt /root 2>/dev/null | head -n 100 || log "No suspicious strings found."

section "Custom System Services"
find /etc/systemd/system -type f -name '*.service' -exec grep -Hi 'ExecStart' {} \; 2>/dev/null
ls -l /etc/init.d 2>/dev/null

section "Unexpected Executables in Writable Paths"
find /tmp /var /home -type f -perm /111 -exec file {} \; 2>/dev/null

section "Hidden Files/Folders in /home"
log "Hidden files:"
find /home -name ".*" -type f 2>/dev/null
log "Hidden directories:"
find /home -name ".*" -type d 2>/dev/null

section "Non-official Packages (Unknown Origin)"
comm -23 \
    <(apt list --installed 2>/dev/null | cut -d/ -f1 | sort) \
    <(grep -r '^Package:' /var/lib/apt/lists 2>/dev/null | cut -d' ' -f2 | sort)

section "Firewall Rules"
if command -v iptables &>/dev/null; then
    log "iptables rules:"
    iptables -L -n -v
fi
if command -v nft &>/dev/null; then
    log "nftables rules:"
    nft list ruleset
fi

section "Security Updates Status"
if command -v apt-get &>/dev/null; then
    log "Simulated apt-get upgrade (dry run):"
    apt-get -s upgrade
fi

section "Kernel and OS Information"
uname -a
if command -v lsb_release &>/dev/null; then
    lsb_release -a 2>/dev/null
fi

highlight "✅ Audit complete. Full report: $LOG_FILE"