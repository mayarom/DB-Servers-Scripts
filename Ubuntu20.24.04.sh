#!/bin/bash
# Ubuntu 20.04-24.04 Audit Script - Bash
# Target: Ubuntu 20.04-24.04
# Functions: systemd, snap, journalctl, modern security features

# Initialize variables
hostname=$(hostname)
os="Ubuntu20_24"
date=$(date +%F_%H-%M-%S)
outdir="/tmp/${hostname}_${os}_${date}"

# Create output directory
mkdir -p "$outdir"

echo "Starting Ubuntu 20.04-24.04 audit - $date"
echo "Output directory: $outdir"

# 1. System Information
{
    echo "hostname,os_release,kernel,architecture,uptime"
    os_release=$(lsb_release -d 2>/dev/null | cut -f2 | tr ',' ' ')
    uptime_info=$(uptime | awk '{print $3,$4}' | sed 's/,//')
    echo "$hostname,$os_release,$(uname -r),$(uname -m),$uptime_info"
} > "$outdir/system_info.csv"

# Detailed system info
lsb_release -a > "$outdir/ubuntu_version.txt" 2>/dev/null
cat /etc/os-release > "$outdir/os_release.txt" 2>/dev/null
hostnamectl > "$outdir/hostname_info.txt" 2>/dev/null

# 2. Users (as specified)
{
    echo "username,uid,gid,home_dir,shell"
    getent passwd | awk -F: '$3 >= 1000 && $1 != "nobody" { print $1","$3","$4","$6","$7 }'
} > "$outdir/linux_users.csv"

# Extended user information
{
    echo "username,uid,gid,home_dir,shell,gecos,account_type,last_login"
    while IFS=: read -r username _ uid gid gecos home shell; do
        gecos_clean=$(echo "$gecos" | tr ',' ';')
        if [[ $uid -eq 0 ]]; then
            account_type="root"
        elif [[ $uid -lt 1000 ]]; then
            account_type="system"
        elif [[ $uid -eq 65534 ]]; then
            account_type="nobody"
        else
            account_type="user"
        fi
        last_login=$(last -1 "$username" 2>/dev/null | head -1 | awk '{print $4" "$5" "$6" "$7}' || echo "never")
        echo "$username,$uid,$gid,$home,$shell,$gecos_clean,$account_type,$last_login"
    done < <(getent passwd)
} > "$outdir/all_users_detailed.csv"

# Privileged users
{
    echo "type,username,source"
    echo "root,root,system"

    # Sudo group members
    if getent group sudo >/dev/null 2>&1; then
        while IFS= read -r user; do
            [[ -n "$user" ]] && echo "sudo,$user,group"
        done < <(getent group sudo | cut -d: -f4 | tr ',' '\n')
    fi

    # Admin group members
    if getent group admin >/dev/null 2>&1; then
        while IFS= read -r user; do
            [[ -n "$user" ]] && echo "admin,$user,group"
        done < <(getent group admin | cut -d: -f4 | tr ',' '\n')
    fi

    # Sudoers entries
    if [[ -r /etc/sudoers ]]; then
        while IFS= read -r line; do
            user=$(echo "$line" | awk '{print $1}')
            echo "sudoers,$user,file"
        done < <(grep -E "^[^#%]*[[:space:]]+ALL.*ALL" /etc/sudoers)
    fi
} > "$outdir/privileged_users.csv"

# 3. Snap Packages (as specified)
if command -v snap >/dev/null 2>&1; then
    # Basic snap list
    snap list | awk 'NR==1 || $1 !~ /^Name$/ { print }' > "$outdir/snap.csv"

    # Detailed snap information
    {
        echo "snap_name,version,revision,tracking,publisher,confinement,devmode,jailmode,private,notes"
        snap list | tail -n +2 | while IFS= read -r name version rev tracking publisher notes; do
            # Get additional snap info
            snap_info=$(snap info "$name" 2>/dev/null)
            confinement=$(echo "$snap_info" | grep "confinement:" | awk '{print $2}' || echo "unknown")
            devmode=$(echo "$notes" | grep -o "devmode" || echo "no")
            jailmode=$(echo "$notes" | grep -o "jailmode" || echo "no")
            private=$(echo "$notes" | grep -o "private" || echo "no")

            echo "$name,$version,$rev,$tracking,$publisher,$confinement,$devmode,$jailmode,$private,$notes"
        done
    } > "$outdir/snap_detailed.csv" 2>/dev/null

    # Snap security analysis
    {
        echo "snap_name,confinement,security_risk,recommendation"
        snap list | tail -n +2 | while IFS= read -r name version rev tracking publisher notes; do
            confinement=$(snap info "$name" 2>/dev/null | grep "confinement:" | awk '{print $2}')

            case "$confinement" in
                "strict") risk="LOW"; rec="Good - confined snap" ;;
                "classic") risk="MEDIUM"; rec="Review - full system access" ;;
                "devmode") risk="HIGH"; rec="Danger - development mode snap" ;;
                *) risk="UNKNOWN"; rec="Manual review required" ;;
            esac

            echo "$name,$confinement,$risk,$rec"
        done
    } > "$outdir/snap_security.csv" 2>/dev/null
else
    echo "snap not available" > "$outdir/snap_error.txt"
fi

# 4. Failed Services (as specified)
systemctl list-units --state=failed > "$outdir/services_failed.csv"

# Extended service analysis
{
    echo "service_name,load_state,active_state,sub_state,enabled_state,failed_reason"
    while IFS= read -r unit load active sub description; do
        if [[ "$unit" == *.service ]]; then
            service_name="${unit%.service}"
            enabled=$(systemctl is-enabled "$unit" 2>/dev/null || echo "unknown")
            failed_reason=$(systemctl status "$unit" 2>/dev/null | grep "Reason:" | cut -d':' -f2 | xargs || echo "unknown")
            echo "$service_name,$load,$active,$sub,$enabled,$failed_reason"
        fi
    done < <(systemctl list-units --state=failed --no-pager --no-legend)
} > "$outdir/failed_services_detailed.csv"

# All services status
{
    echo "service_name,load_state,active_state,sub_state,enabled_state"
    while IFS= read -r unit state; do
        if [[ "$unit" == *.service ]]; then
            service_name="${unit%.service}"
            load_state=$(systemctl show "$unit" --property=LoadState --value 2>/dev/null)
            active_state=$(systemctl show "$unit" --property=ActiveState --value 2>/dev/null)
            sub_state=$(systemctl show "$unit" --property=SubState --value 2>/dev/null)
            echo "$service_name,$load_state,$active_state,$sub_state,$state"
        fi
    done < <(systemctl list-unit-files --type=service --no-pager --no-legend)
} > "$outdir/all_services.csv"

# 5. System Errors from Last 7 Days (as specified)
journalctl -p err --since "7 days ago" > "$outdir/errors.txt"

# Additional log analysis
{
    echo "priority,count,sample_message"
    for priority in emerg alert crit err warning; do
        count=$(journalctl -p "$priority" --since "7 days ago" --no-pager -q | wc -l)
        sample=$(journalctl -p "$priority" --since "7 days ago" --no-pager -q | head -1 | cut -c1-100)
        echo "$priority,$count,$sample"
    done
} > "$outdir/log_summary.csv"

# Security-related logs
journalctl -u ssh --since "7 days ago" > "$outdir/ssh_logs.txt" 2>/dev/null
journalctl -u ufw --since "7 days ago" > "$outdir/ufw_logs.txt" 2>/dev/null
journalctl -u apparmor --since "7 days ago" > "$outdir/apparmor_logs.txt" 2>/dev/null

# 6. SSH Configuration (as specified)
if [[ -f /etc/ssh/sshd_config ]]; then
    # Basic SSH config extraction
    grep -Ei '^(PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config > "$outdir/ssh_config.txt"

    # Full SSH config
    cp /etc/ssh/sshd_config "$outdir/sshd_config_full.txt"

    # SSH security analysis
    {
        echo "setting,value,security_level,recommendation"

        permit_root=$(grep -i "^[[:space:]]*PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}' | tail -1)
        password_auth=$(grep -i "^[[:space:]]*PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}' | tail -1)
        pubkey_auth=$(grep -i "^[[:space:]]*PubkeyAuthentication" /etc/ssh/sshd_config | awk '{print $2}' | tail -1)
        port=$(grep -i "^[[:space:]]*Port" /etc/ssh/sshd_config | awk '{print $2}' | tail -1)
        max_auth=$(grep -i "^[[:space:]]*MaxAuthTries" /etc/ssh/sshd_config | awk '{print $2}' | tail -1)
        client_alive=$(grep -i "^[[:space:]]*ClientAliveInterval" /etc/ssh/sshd_config | awk '{print $2}' | tail -1)

        # Security evaluation
        [[ "$permit_root" = "no" ]] && root_risk="OK" || root_risk="HIGH"
        [[ "$password_auth" = "no" ]] && pass_risk="OK" || pass_risk="MEDIUM"
        [[ "$pubkey_auth" = "yes" ]] && key_risk="OK" || key_risk="MEDIUM"
        [[ "$port" != "22" && -n "$port" ]] && port_risk="OK" || port_risk="INFO"
        [[ "$max_auth" -le "3" && -n "$max_auth" ]] && auth_risk="OK" || auth_risk="MEDIUM"

        echo "PermitRootLogin,${permit_root:-default},$root_risk,Set to 'no' for security"
        echo "PasswordAuthentication,${password_auth:-default},$pass_risk,Set to 'no' and use key-based auth"
        echo "PubkeyAuthentication,${pubkey_auth:-default},$key_risk,Set to 'yes' for key-based auth"
        echo "Port,${port:-22},$port_risk,Consider non-standard port"
        echo "MaxAuthTries,${max_auth:-6},$auth_risk,Set to 3 or lower"
        echo "ClientAliveInterval,${client_alive:-0},INFO,Consider setting to 300"
    } > "$outdir/ssh_security_analysis.csv"
else
    echo "SSH config not found" > "$outdir/ssh_error.txt"
fi

# 7. Package Management
if command -v apt >/dev/null 2>&1; then
    # Available updates
    apt list --upgradable > "$outdir/updates.txt" 2>/dev/null

    # Security updates specifically
    apt list --upgradable 2>/dev/null | grep -i security > "$outdir/security_updates.txt"

    # Installed packages
    {
        echo "package_name,version,architecture,status,priority"
        dpkg-query -W -f='${Package},${Version},${Architecture},${Status},${Priority}\n'
    } > "$outdir/installed_packages.csv"

    # Recently updated packages
    grep " install \| upgrade " /var/log/dpkg.log | tail -100 > "$outdir/recent_package_changes.txt" 2>/dev/null

    # Package sources and repositories
    {
        echo "repository,components,architectures"
        grep -h "^deb " /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | while IFS= read -r line; do
            repo=$(echo "$line" | awk '{print $2}')
            components=$(echo "$line" | awk '{for(i=4;i<=NF;i++) printf "%s ", $i}')
            arch=$(echo "$line" | awk '{print $3}')
            echo "$repo,$components,$arch"
        done
    } > "$outdir/apt_repositories.csv"
fi

# 8. UFW Firewall
if command -v ufw >/dev/null 2>&1; then
    # Basic status
    ufw status > "$outdir/firewall.txt" 2>/dev/null
    ufw status verbose > "$outdir/ufw_verbose.txt" 2>/dev/null
    ufw status numbered > "$outdir/ufw_numbered.txt" 2>/dev/null

    # UFW rules in CSV format
    {
        echo "rule_number,action,from,to,port,protocol"
        ufw status numbered | grep -E "^\[" | while IFS= read -r line; do
            rule_num=$(echo "$line" | grep -o "\[[0-9]*\]" | tr -d "[]")
            rule_text=$(echo "$line" | sed 's/\[[0-9]*\] *//')
            action=$(echo "$rule_text" | awk '{print $1}')
            remaining=$(echo "$rule_text" | cut -d' ' -f2- | tr ' ' ',')
            echo "$rule_num,$action,$remaining"
        done
    } > "$outdir/ufw_rules.csv" 2>/dev/null
else
    # Fallback to iptables
    iptables -L -n > "$outdir/iptables_fallback.txt" 2>/dev/null
fi

# 9. AppArmor (Ubuntu default LSM)
if command -v aa-status >/dev/null 2>&1; then
    aa-status > "$outdir/apparmor_status.txt" 2>/dev/null

    {
        echo "profile,mode,path"
        aa-status --enabled 2>/dev/null | while IFS= read -r profile; do
            echo "$profile,enforce,/etc/apparmor.d/"
        done
        aa-status --complain 2>/dev/null | while IFS= read -r profile; do
            echo "$profile,complain,/etc/apparmor.d/"
        done
    } > "$outdir/apparmor_profiles.csv" 2>/dev/null
else
    echo "AppArmor not available" > "$outdir/apparmor_error.txt"
fi

# 10. Cron Jobs and Scheduled Tasks
{
    echo "type,user,schedule,command,file"

    # System crontab
    if [[ -f /etc/crontab ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^[0-9*] ]]; then
                schedule=$(echo "$line" | awk '{print $1" "$2" "$3" "$4" "$5}')
                user=$(echo "$line" | awk '{print $6}')
                command=$(echo "$line" | awk '{for(i=7;i<=NF;i++) printf "%s ", $i; print ""}')
                echo "system,$user,$schedule,$command,/etc/crontab"
            fi
        done < <(grep -v "^#" /etc/crontab | grep -v "^$")
    fi

    # User crontabs
    while IFS=: read -r user _; do
        if crontab -u "$user" -l >/dev/null 2>&1; then
            while IFS= read -r line; do
                schedule=$(echo "$line" | awk '{print $1" "$2" "$3" "$4" "$5}')
                command=$(echo "$line" | awk '{for(i=6;i<=NF;i++) printf "%s ", $i; print ""}')
                echo "user,$user,$schedule,$command,crontab"
            done < <(crontab -u "$user" -l 2>/dev/null | grep -v "^#" | grep -v "^$")
        fi
    done < /etc/passwd

    # Systemd timers
    while IFS= read -r next left _ _ unit activates; do
        if [[ "$unit" != "NEXT" && "$unit" != "n/a" ]]; then
            schedule="$next $left"
            echo "systemd,root,$schedule,$activates,systemd-timer"
        fi
    done < <(systemctl list-timers --no-pager --no-legend 2>/dev/null)
} > "$outdir/cron.txt"

# 11. Network Security
{
    echo "interface,ip_address,prefix,scope,state"
    ip -4 addr show | awk '
    /^[0-9]+:/ {
        interface = $2;
        gsub(/:/, "", interface);
        state = $9
    }
    /inet / {
        split($2, addr, "/");
        print interface","addr[1]","addr[2]","$4","state
    }'
} > "$outdir/network_interfaces.csv"

# Open ports and services
{
    echo "protocol,local_address,local_port,service,state"
    ss -tuln | awk 'NR>1 {
        split($4, local_addr, ":");
        local_port = local_addr[length(local_addr)];
        print $1","$4","local_port",unknown,"$2
    }'
} > "$outdir/listening_ports.csv"

# 12. Security Updates and Patches
# Unattended upgrades configuration
if [[ -f /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
    cp /etc/apt/apt.conf.d/50unattended-upgrades "$outdir/unattended_upgrades.txt"
fi

# Check for automatic updates
{
    echo "setting,value,file"
    if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^APT:: ]]; then
                setting=$(echo "$line" | cut -d'"' -f2)
                value=$(echo "$line" | cut -d'"' -f4)
                echo "$setting,$value,20auto-upgrades"
            fi
        done < <(grep -v "^//" /etc/apt/apt.conf.d/20auto-upgrades)
    fi
} > "$outdir/auto_updates_config.csv"

# 13. Security Tools and Features
{
    echo "tool,status,version,notes"

    # Common security tools
    security_tools=("fail2ban" "ufw" "apparmor-utils" "rkhunter" "chkrootkit" "aide" "clamav")

    for tool in "${security_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            version=$("$tool" --version 2>/dev/null | head -1 || echo "installed")
            status="installed"
        elif dpkg -l | grep -q "^ii.*$tool "; then
            version=$(dpkg -l | grep "^ii.*$tool " | awk '{print $3}')
            status="installed"
        else
            version="N/A"
            status="not_installed"
        fi
        echo "$tool,$status,$version,Security tool"
    done

    # Check for specific Ubuntu security features
    if [[ -f /proc/sys/kernel/yama/ptrace_scope ]]; then
        ptrace_val=$(cat /proc/sys/kernel/yama/ptrace_scope)
        echo "ptrace_scope,enabled,$ptrace_val,Yama LSM protection"
    fi

    # Check if Ubuntu Pro is enabled
    if command -v pro >/dev/null 2>&1; then
        pro_status=$(pro status --format json 2>/dev/null | grep -o '"attached":[^,]*' | cut -d':' -f2 | tr -d '"' || echo "unknown")
        echo "ubuntu_pro,$pro_status,N/A,Extended security updates"
    fi
} > "$outdir/security_tools.csv"

# 14. File System Security
{
    echo "filesystem,mount_point,type,options,security_concern"
    while IFS= read -r device _ mount _ fstype options; do
        concern="OK"

        # Check mount options for security
        case "$mount" in
            "/tmp"|"/var/tmp")
                [[ "$options" != *nosuid* ]] && concern="MEDIUM: Missing nosuid"
                [[ "$options" != *noexec* ]] && concern="HIGH: Missing noexec"
                [[ "$options" != *nodev* ]] && concern="MEDIUM: Missing nodev"
                ;;
            "/dev/shm")
                [[ "$options" != *nosuid* ]] && concern="HIGH: /dev/shm without nosuid"
                [[ "$options" != *noexec* ]] && concern="CRITICAL: /dev/shm without noexec"
                ;;
            "/home")
                [[ "$options" != *nodev* ]] && concern="MEDIUM: /home without nodev"
                ;;
        esac

        echo "$device,$mount,$fstype,$options,$concern"
    done < <(mount)
} > "$outdir/filesystem_security.csv"

# 15. Generate Summary Report
user_count=$(tail -n +2 "$outdir/linux_users.csv" 2>/dev/null | wc -l)
admin_count=$(tail -n +2 "$outdir/privileged_users.csv" 2>/dev/null | wc -l)
failed_services=$(tail -n +2 "$outdir/failed_services_detailed.csv" 2>/dev/null | wc -l)
snap_count=$(tail -n +2 "$outdir/snap_detailed.csv" 2>/dev/null | wc -l)
error_count=$(journalctl -p err --since "7 days ago" --no-pager -q | wc -l)
ufw_status=$(grep -o "Status: [a-z]*" "$outdir/firewall.txt" 2>/dev/null | cut -d' ' -f2 || echo "unknown")

{
    echo "Ubuntu 20.04-24.04 Security Audit Summary"
    echo "========================================="
    echo "Server: $hostname"
    echo "Date: $date"
    echo "OS: $(lsb_release -d 2>/dev/null | cut -f2 || echo 'Unknown')"
    echo "Kernel: $(uname -r)"
    echo "UFW Status: $ufw_status"
    echo ""
    echo "Users (UID >= 1000): $user_count"
    echo "Privileged Users: $admin_count"
    echo "Failed Services: $failed_services"
    echo "Snap Packages: $snap_count"
    echo "System Errors (7 days): $error_count"
    echo ""
    echo "Key Files:"
    echo "- linux_users.csv (users with UID >= 1000)"
    echo "- snap.csv (installed snap packages)"
    echo "- services_failed.csv (failed systemd services)"
    echo "- errors.txt (system errors from last 7 days)"
    echo "- ssh_config.txt (SSH security settings)"
    echo "- updates.txt (available package updates)"
    echo "- firewall.txt (UFW firewall status)"
    echo ""
    echo "Files generated in: $outdir"
} > "$outdir/AUDIT_SUMMARY.txt"

echo "Ubuntu 20.04-24.04 audit completed"
echo "Files saved to: $outdir"