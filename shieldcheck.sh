#!/bin/bash
#
# shieldcheck - Quick server security status check
# https://github.com/uppinote20/shieldcheck
#
# Usage: curl -sSL https://raw.githubusercontent.com/uppinote20/shieldcheck/main/shieldcheck.sh | sudo bash
#

set -uo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# Symbols
CHECK="✓"
CROSS="✗"
WARN="!"
ARROW="→"

# Results storage
declare -A RESULTS
WARNINGS=()
SUGGESTIONS=()

#######################################
# Utility functions
#######################################

print_header() {
    local hostname=$(hostname)
    local date=$(date '+%Y-%m-%d %H:%M:%S')
    echo ""
    echo -e "${BOLD}${BLUE}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}${BLUE}│${NC}  ${BOLD}🛡️  shieldcheck${NC}                                            ${BOLD}${BLUE}│${NC}"
    echo -e "${BOLD}${BLUE}│${NC}  ${DIM}${hostname} · ${date}${NC}              ${BOLD}${BLUE}│${NC}"
    echo -e "${BOLD}${BLUE}├─────────────────────────────────────────────────────────────┤${NC}"
}

print_section() {
    local title="$1"
    echo -e "${BOLD}${BLUE}│${NC}"
    echo -e "${BOLD}${BLUE}│${NC}  ${BOLD}${title}${NC}"
    echo -e "${BOLD}${BLUE}│${NC}  ${DIM}─────────────────────────────────────${NC}"
}

print_item() {
    local label="$1"
    local status="$2"
    local detail="${3:-}"

    local status_icon status_color
    case "$status" in
        ok)     status_icon="$CHECK"; status_color="$GREEN" ;;
        warn)   status_icon="$WARN";  status_color="$YELLOW" ;;
        fail)   status_icon="$CROSS"; status_color="$RED" ;;
        *)      status_icon="?";      status_color="$NC" ;;
    esac

    if [[ -n "$detail" ]]; then
        printf "${BOLD}${BLUE}│${NC}    ${status_color}${status_icon}${NC}  %-28s ${DIM}%s${NC}\n" "$label" "$detail"
    else
        printf "${BOLD}${BLUE}│${NC}    ${status_color}${status_icon}${NC}  %s\n" "$label"
    fi
}

print_stat() {
    local label="$1"
    local value="$2"
    printf "${BOLD}${BLUE}│${NC}    %-20s ${BOLD}%s${NC}\n" "$label" "$value"
}

print_detail() {
    local text="$1"
    echo -e "${BOLD}${BLUE}│${NC}      ${DIM}${text}${NC}"
}

print_footer() {
    local warn_count=${#WARNINGS[@]}
    local sugg_count=${#SUGGESTIONS[@]}

    echo -e "${BOLD}${BLUE}│${NC}"
    echo -e "${BOLD}${BLUE}├─────────────────────────────────────────────────────────────┤${NC}"

    if [[ $warn_count -eq 0 && $sugg_count -eq 0 ]]; then
        echo -e "${BOLD}${BLUE}│${NC}  ${GREEN}${CHECK} All checks passed${NC}"
    else
        if [[ $warn_count -gt 0 ]]; then
            echo -e "${BOLD}${BLUE}│${NC}  ${YELLOW}${WARN} Warnings: ${warn_count}${NC}"
            for w in "${WARNINGS[@]}"; do
                echo -e "${BOLD}${BLUE}│${NC}    ${DIM}${ARROW} ${w}${NC}"
            done
        fi
        if [[ $sugg_count -gt 0 ]]; then
            echo -e "${BOLD}${BLUE}│${NC}  ${CYAN}💡 Suggestions: ${sugg_count}${NC}"
            for s in "${SUGGESTIONS[@]}"; do
                echo -e "${BOLD}${BLUE}│${NC}    ${DIM}${ARROW} ${s}${NC}"
            done
        fi
    fi

    echo -e "${BOLD}${BLUE}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

#######################################
# Check functions
#######################################

check_ssh() {
    print_section "SSH Security"

    # Check if sshd is running
    if ! command -v sshd &> /dev/null; then
        print_item "SSH Server" "warn" "not installed"
        return
    fi

    # Get SSH config
    local ssh_config
    ssh_config=$(sshd -T 2>/dev/null) || {
        print_item "SSH Config" "warn" "cannot read (run as root)"
        return
    }

    # Password Authentication
    local pass_auth=$(echo "$ssh_config" | grep "^passwordauthentication" | awk '{print $2}')
    if [[ "$pass_auth" == "no" ]]; then
        print_item "Password Auth" "ok" "disabled"
    else
        print_item "Password Auth" "fail" "enabled"
        WARNINGS+=("Password authentication is enabled - use key-based auth")
    fi

    # Root Login
    local root_login=$(echo "$ssh_config" | grep "^permitrootlogin" | awk '{print $2}')
    if [[ "$root_login" == "no" ]]; then
        print_item "Root Login" "ok" "disabled"
    elif [[ "$root_login" == "without-password" || "$root_login" == "prohibit-password" ]]; then
        print_item "Root Login" "warn" "key-only"
        SUGGESTIONS+=("Consider setting PermitRootLogin to 'no'")
    else
        print_item "Root Login" "fail" "enabled"
        WARNINGS+=("Root login is enabled")
    fi

    # MaxAuthTries
    local max_tries=$(echo "$ssh_config" | grep "^maxauthtries" | awk '{print $2}')
    if [[ "$max_tries" -le 3 ]]; then
        print_item "Max Auth Tries" "ok" "$max_tries"
    elif [[ "$max_tries" -le 6 ]]; then
        print_item "Max Auth Tries" "warn" "$max_tries"
        SUGGESTIONS+=("Consider lowering MaxAuthTries to 3")
    else
        print_item "Max Auth Tries" "fail" "$max_tries"
        WARNINGS+=("MaxAuthTries is too high ($max_tries)")
    fi

    # Pubkey Authentication
    local pubkey=$(echo "$ssh_config" | grep "^pubkeyauthentication" | awk '{print $2}')
    if [[ "$pubkey" == "yes" ]]; then
        print_item "Pubkey Auth" "ok" "enabled"
    else
        print_item "Pubkey Auth" "fail" "disabled"
        WARNINGS+=("Public key authentication is disabled")
    fi
}

check_firewall() {
    print_section "Firewall"

    # Check UFW
    if command -v ufw &> /dev/null; then
        local ufw_status=$(ufw status 2>/dev/null | head -1)
        if [[ "$ufw_status" == *"active"* ]]; then
            print_item "UFW" "ok" "active"

            # Show open ports with details
            local open_ports=$(ufw status | grep "ALLOW" | grep -v "(v6)" | awk '{print $1}' | tr '\n' ' ')
            if [[ -n "$open_ports" ]]; then
                print_detail "Allowed: ${open_ports}"
            fi
        else
            print_item "UFW" "fail" "inactive"
            WARNINGS+=("UFW firewall is not active")
        fi
    else
        print_item "UFW" "warn" "not installed"
    fi
}

check_fail2ban() {
    print_section "Intrusion Prevention (fail2ban)"

    if ! command -v fail2ban-client &> /dev/null; then
        print_item "fail2ban" "fail" "not installed"
        WARNINGS+=("fail2ban is not installed")
        return
    fi

    # Check if running
    if ! fail2ban-client ping &>/dev/null; then
        print_item "fail2ban" "fail" "not running"
        WARNINGS+=("fail2ban is installed but not running")
        return
    fi

    print_item "fail2ban" "ok" "running"

    # Get jail list
    local jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,//g' | xargs)

    if [[ -z "$jails" ]]; then
        print_item "Active Jails" "warn" "none"
        SUGGESTIONS+=("Configure fail2ban jails")
        return
    fi

    # Check sshd jail
    if [[ "$jails" == *"sshd"* ]]; then
        local sshd_status=$(fail2ban-client status sshd 2>/dev/null)
        local currently_banned=$(echo "$sshd_status" | grep "Currently banned" | awk '{print $NF}')
        local total_banned=$(echo "$sshd_status" | grep "Total banned" | awk '{print $NF}')
        local total_failed=$(echo "$sshd_status" | grep "Total failed" | awk '{print $NF}')

        print_item "sshd jail" "ok" "active"
        print_stat "  Currently banned:" "$currently_banned IPs"
        print_stat "  Total banned:" "$total_banned"
        print_stat "  Failed attempts:" "$total_failed"
    else
        print_item "sshd jail" "warn" "not configured"
        SUGGESTIONS+=("Enable fail2ban sshd jail")
    fi

    # Check recidive jail
    if [[ "$jails" == *"recidive"* ]]; then
        local recidive_status=$(fail2ban-client status recidive 2>/dev/null)
        local recidive_banned=$(echo "$recidive_status" | grep "Currently banned" | awk '{print $NF}')
        print_item "recidive jail" "ok" "$recidive_banned long-term bans"
    else
        print_item "recidive jail" "warn" "not configured"
        SUGGESTIONS+=("Enable recidive jail for repeat offenders")
    fi
}

check_compromise() {
    print_section "Compromise Indicators"

    local issues=0

    # Check for suspicious users (UID >= 1000, excluding standard users)
    local suspicious_users=$(awk -F: '$3 >= 1000 && $3 < 65534 && $1 !~ /^(ubuntu|opc|admin|ec2-user|centos|debian)$/ {print $1}' /etc/passwd 2>/dev/null | head -5)
    if [[ -z "$suspicious_users" ]]; then
        print_item "User accounts" "ok" "no suspicious users"
    else
        print_item "User accounts" "warn" "review: $suspicious_users"
        SUGGESTIONS+=("Review user accounts: $suspicious_users")
        ((issues++)) || true
    fi

    # Check for multiple SSH keys
    local auth_keys="$HOME/.ssh/authorized_keys"
    if [[ -f "$auth_keys" ]]; then
        local key_count
        key_count=$(grep -c "^ssh-" "$auth_keys" 2>/dev/null) || key_count=0
        if [[ "$key_count" -le 2 ]]; then
            print_item "SSH keys" "ok" "$key_count authorized"
        else
            print_item "SSH keys" "warn" "$key_count keys (review)"
            SUGGESTIONS+=("Review authorized SSH keys")
            ((issues++)) || true
        fi
        # Show key comments (last field)
        grep "^ssh-" "$auth_keys" 2>/dev/null | while read -r line; do
            local comment=$(echo "$line" | awk '{print $NF}')
            print_detail "→ ${comment}"
        done
    else
        print_item "SSH keys" "ok" "no keys file"
    fi

    # Check for suspicious cron jobs
    local cron_jobs=$(crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | wc -l)
    local system_crons=$(ls /etc/cron.d/ 2>/dev/null | grep -v "^\\." | wc -l)
    print_item "Cron jobs" "ok" "$cron_jobs user, $system_crons system"
    # Show user cron details
    if [[ "$cron_jobs" -gt 0 ]]; then
        crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | while read -r line; do
            local cmd=$(echo "$line" | awk '{for(i=6;i<=NF;i++) printf $i" "; print ""}' | cut -c1-50)
            print_detail "→ ${cmd}"
        done
    fi
    # Show system cron names
    if [[ "$system_crons" -gt 0 ]]; then
        local cron_names=$(ls /etc/cron.d/ 2>/dev/null | grep -v "^\\." | tr '\n' ' ')
        print_detail "System: ${cron_names}"
    fi

    # Check for suspicious processes (crypto miners, etc.)
    local suspicious_procs=$(ps aux 2>/dev/null | grep -iE "(xmrig|minerd|cryptonight|stratum)" | grep -v grep | wc -l)
    if [[ "$suspicious_procs" -eq 0 ]]; then
        print_item "Suspicious processes" "ok" "none detected"
    else
        print_item "Suspicious processes" "fail" "$suspicious_procs found!"
        WARNINGS+=("Suspicious processes detected - possible cryptominer")
        ((issues++)) || true
    fi

    # Check for unusual network connections
    local outbound=$(ss -tunap 2>/dev/null | grep ESTAB | grep -v "127.0.0.1\|::1" | wc -l)
    print_item "Outbound connections" "ok" "$outbound active"
    # Show connection details
    ss -tunap 2>/dev/null | grep ESTAB | grep -v "127.0.0.1\|::1" | while read -r line; do
        local proc=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "unknown")
        local remote=$(echo "$line" | awk '{print $6}')
        # Clean up IPv6-mapped IPv4 addresses
        remote=$(echo "$remote" | sed 's/\[::ffff://' | sed 's/\]//' | sed 's/::ffff://')
        print_detail "→ ${proc} → ${remote}"
    done

    # Check last logins for unusual IPs
    local unique_ips=$(last -ai 2>/dev/null | grep -v "reboot\|wtmp\|^$" | awk '{print $NF}' | sort -u | wc -l)
    print_item "Unique login IPs" "ok" "$unique_ips (last month)"

    # Get top IPs with counts
    local top_ips=$(last -ai 2>/dev/null | grep -v "reboot\|wtmp\|^$" | awk '{print $NF}' | sort | uniq -c | sort -rn | head -5)
    local most_common_ip=$(echo "$top_ips" | head -1 | awk '{print $2}')

    # Show top login IPs with GeoIP info
    echo "$top_ips" | while read -r count ip; do
        # Skip invalid IPs
        [[ -z "$ip" || "$ip" == "0.0.0.0" ]] && continue

        # Get GeoIP info (with timeout)
        local geoinfo=$(curl -s --max-time 2 "http://ip-api.com/json/${ip}?fields=countryCode,isp,mobile" 2>/dev/null)

        if [[ -n "$geoinfo" && "$geoinfo" != *"fail"* ]]; then
            local country=$(echo "$geoinfo" | grep -o '"countryCode":"[^"]*"' | cut -d'"' -f4)
            local isp=$(echo "$geoinfo" | grep -o '"isp":"[^"]*"' | cut -d'"' -f4 | cut -c1-20)
            local mobile=$(echo "$geoinfo" | grep -o '"mobile":[^,}]*' | cut -d':' -f2)

            local tag=""
            [[ "$mobile" == "true" ]] && tag=" [Mobile]"
            [[ "$count" -eq 1 ]] && tag="${tag} [NEW]"

            print_detail "→ ${ip} (${count}x) ${country}, ${isp}${tag}"
        else
            print_detail "→ ${ip} (${count}x)"
        fi
    done

    if [[ $issues -eq 0 ]]; then
        RESULTS[compromise]="clean"
    else
        RESULTS[compromise]="review"
    fi
}

check_updates() {
    print_section "System Updates"

    # Check unattended-upgrades
    if dpkg -l unattended-upgrades &>/dev/null 2>&1; then
        print_item "Auto security updates" "ok" "configured"
    elif command -v dnf &>/dev/null && dnf list installed dnf-automatic &>/dev/null 2>&1; then
        print_item "Auto security updates" "ok" "configured (dnf)"
    else
        print_item "Auto security updates" "warn" "not configured"
        SUGGESTIONS+=("Enable automatic security updates")
    fi

    # Check for pending updates (quick check)
    if command -v apt &>/dev/null; then
        local security_updates=$(apt list --upgradable 2>/dev/null | grep -i security | wc -l)
        if [[ "$security_updates" -eq 0 ]]; then
            print_item "Pending security updates" "ok" "none"
        else
            print_item "Pending security updates" "warn" "$security_updates available"
            SUGGESTIONS+=("Apply pending security updates")
        fi
    fi
}

#######################################
# Main
#######################################

main() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}Warning: Running without root. Some checks may be limited.${NC}"
        echo -e "${DIM}Run with: sudo $0${NC}"
        echo ""
    fi

    print_header

    check_ssh
    check_firewall
    check_fail2ban
    check_compromise
    check_updates

    print_footer
}

main "$@"
