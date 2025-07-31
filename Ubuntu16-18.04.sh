#!/bin/bash
# Ubuntu 16.04-18.04 Audit Script - Bash
# Target: Ubuntu 16.04-18.04
# Functions: apt updates, ufw firewall, users, SSH, AppArmor

# Initialize variables
hostname=$(hostname)
os="Ubuntu16_18"
date=$(date +%F_%H-%M-%S)
outdir="/tmp/${hostname}_${os}_${date}"

# Create output directory
mkdir -p "$outdir"

echo "Starting Ubuntu 16.04-18.04 audit - $date"
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
uname -a > "$outdir/kernel_info.txt"
hostnamectl > "$outdir/hostname_info.txt" 2>/dev/null

# 2. Users and Groups
{
    echo "username,uid,gid,home_dir,shell,gecos"
    while IFS=: read -r username _ uid gid gecos home shell; do
        if [[ $uid -ge 1000 && $uid -ne 65534 ]]; then
            gecos_clean=$(echo "$gecos" | tr ',' ';')
            echo "$username,$uid,$gid,$home,$shell,$gecos_clean"
        fi
    done < <(getent passwd)
} > "$outdir/linux_users.csv"

# All users including system
{
    echo "username,uid,gid,home_dir,shell,gecos,account_type"
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
        echo "$username,$uid,$gid,$home,$shell,$gecos_clean,$account_type"
    done < <(getent passwd)
} > "$outdir/all_users.csv"

# Privileged users (sudo group)
{
    echo "type,username,source"
    echo "root,root,system"

    # Sudo group members
    if getent group sudo >/dev/null 2>&1; then
        while IFS= read -r user; do
            [[ -n "$user" ]] && echo "sudo,$user,group"
        done < <(getent group sudo | cut -d: -f4 | tr ',' '\n')
    fi

    # Admin group members (Ubuntu legacy)
    if getent group admin >/dev/null 2>&1; then
        while IFS= read -r user; do
            [[ -n "$user" ]] && echo "admin,$user,group"
        done < <(getent group admin | cut -d: -f4 | tr ',' '\n')
    fi

    # Sudoers file entries
    if [[ -r /etc/sudoers ]]; then
        while IFS= read -r line; do
            echo "sudoers,$(echo "$line" | awk '{print $1}'),file"
        done < <(grep -E "^[^#%]*[[:space:]]+ALL.*ALL" /etc/sudoers)
    fi

    # Sudoers.d directory
    if [[ -d /etc/sudoers.d ]]; then
        find /etc/sudoers.d -type f | while IFS= read -r file; do
            while IFS= read -r line; do
                echo "sudoers,$(echo "$line" | awk '{print $1}'),sudoers.d/$(basename "$file")"
            done < <(grep -E "^[^#%]*[[:space:]]+ALL.*ALL" "$file" 2>/dev/null)
        done
    fi
} > "$outdir/privileged_users.csv"

# 3. Package Management with APT
if command -v apt >/dev/null 2>&1; then
    # Available upgrades
    apt list --upgradable > "$outdir/available_updates.txt" 2>/dev/null

    # Security updates
    apt list --upgradable | grep -i security > "$outdir/security_updates.txt" 2>/dev/null

    # Package sources
    cp /etc/apt/sources.list "$outdir/apt_sources.txt" 2>/dev/null
    if [[ -d /etc/apt/sources.list.d ]]; then
        find /etc/apt/sources.list.d -name "*.list" -exec cat {} \; > "$outdir/apt_sources_additional.txt" 2>/dev/null
    fi

    # Installed packages
    {
        echo "package_name,version,architecture,status"
        dpkg-query -W -f='${Package},${Version},${Architecture},${Status}\n' | grep "install ok installed"
    } > "$outdir/installed_packages.csv"

    # Recently installed packages
    grep " install " /var/log/dpkg.log | tail -50 > "$outdir/recent_installations.txt" 2>/dev/null

    # Package hold list
    apt-mark showhold > "$outdir/held_packages.txt" 2>/dev/null
else
    echo "apt not available" > "$outdir/package_manager_error.txt"
fi

# 4. Services (systemd)
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
} > "$outdir/services.csv"

# Running services
{
    echo "service_name,active_state,main_pid,memory_usage"
    while IFS= read -r unit _ active _ _; do
        service_name="${unit%.service}"
        main_pid=$(systemctl show "$unit" --property=MainPID --value 2>/dev/null)
        memory=$(systemctl show "$unit" --property=MemoryCurrent --value 2>/dev/null)
        echo "$service_name,$active,$main_pid,$memory"
    done < <(systemctl list-units --type=service --state=running --no-pager --no-legend)
} > "$outdir/running_services.csv"

# 5. UFW Firewall Configuration
if command -v ufw >/dev/null 2>&1; then
    # UFW status
    ufw status > "$outdir/ufw_status.txt" 2>/dev/null
    ufw status verbose > "$outdir/ufw_status_verbose.txt" 2>/dev/null
    ufw status numbered > "$outdir/ufw_status_numbered.txt" 2>/dev/null

    # Parse UFW rules to CSV
    {
        echo "action,from,to,port,protocol,comment"
        ufw status numbered | grep -E "^\[" | while IFS= read -r line; do
            # Extract rule components
            rule=$(echo "$line" | sed 's/\[[0-9]*\] *//')
            action=$(echo "$rule" | awk '{print $1}')
            remaining=$(echo "$rule" | cut -d' ' -f2-)
            echo "$action,$remaining,,,,"
        done
    } > "$outdir/ufw_rules.csv" 2>/dev/null

    # UFW application profiles
    ufw app list > "$outdir/ufw_app_profiles.txt" 2>/dev/null
else
    echo "ufw not available" > "$outdir/firewall_error.txt"
fi

# Check iptables as backup
if command -v iptables >/dev/null 2>&1; then
    iptables -L -n > "$outdir/iptables_rules.txt" 2>/dev/null
    iptables -L -n -v > "$outdir/iptables_verbose.txt" 2>/dev/null
fi

# 6. SSH Configuration
if [[ -f /etc/ssh/sshd_config ]]; then
    # Full SSH config
    cp /etc/ssh/sshd_config "$outdir/sshd_config.txt"

    # Key security settings
    {
        echo "setting,value,security_level"

        permit_root=$(grep -i "^[[:space:]]*PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}' | tail -1)
        password_auth=$(grep -i "^[[:space:]]*PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}' | tail -1)
        pubkey_auth=$(grep -i "^[[:space:]]*PubkeyAuthentication" /etc/ssh/sshd_config | awk '{print $2}' | tail -1)
        protocol=$(grep -i "^[[:space:]]*Protocol" /etc/ssh/sshd_config | awk '{print $2}' | tail -1)
        port=$(grep -i "^[[:space:]]*Port" /etc/ssh/sshd_config | awk '{print $2}' | tail -1)
        max_auth=$(grep -i "^[[:space:]]*MaxAuthTries" /etc/ssh/sshd_config | awk '{print $2}' | tail -1)

        # Security evaluation
        [[ "$permit_root" = "no" ]] && root_risk="OK" || root_risk="HIGH"
        [[ "$password_auth" = "no" ]] && pass_risk="OK" || pass_risk="MEDIUM"
        [[ "$pubkey_auth" = "yes" ]] && key_risk="OK" || key_risk="MEDIUM"
        [[ "$port" != "22" ]] && port_risk="OK" || port_risk="INFO"
        [[ "$max_auth" -le "3" ]] && auth_risk="OK" || auth_risk="MEDIUM"

        echo "PermitRootLogin,${permit_root:-default},$root_risk"
        echo "PasswordAuthentication,${password_auth:-default},$pass_risk"
        echo "PubkeyAuthentication,${pubkey_auth:-default},$key_risk"
        echo "Port,${port:-22},$port_risk"
        echo "Protocol,${protocol:-2},OK"
        echo "MaxAuthTries,${max_auth:-6},$auth_risk"
    } > "$outdir/ssh_security_config.csv"

    # SSH service status
    systemctl status ssh > "$outdir/ssh_service_status.txt" 2>/dev/null
else
    echo "SSH config not found" > "$outdir/ssh_error.txt"
fi

# 7. AppArmor (Ubuntu's default LSM)
if command -v aa-status >/dev/null 2>&1; then
    # AppArmor status
    aa-status > "$outdir/apparmor_status.txt" 2>/dev/null

    # AppArmor profiles
    {
        echo "profile,mode"
        aa-status --enabled 2>/dev/null | while IFS= read -r profile; do
            echo "$profile,enforce"
        done
        aa-status --complain 2>/dev/null | while IFS= read -r profile; do
            echo "$profile,complain"
        done
    } > "$outdir/apparmor_profiles.csv" 2>/dev/null

    # AppArmor configuration
    if [[ -d /etc/apparmor.d ]]; then
        find /etc/apparmor.d -name "*" -type f | wc -l > "$outdir/apparmor_profile_count.txt"
    fi
else
    echo "AppArmor not available" > "$outdir/apparmor_error.txt"
fi

# 8. Network Configuration
{
    echo "interface,ip_address,prefix,scope,state"
    ip -4 addr show 2>/dev/null | awk '
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

# Network connections
{
    echo "protocol,local_address,local_port,remote_address,remote_port,state"
    ss -tuln 2>/dev/null | awk 'NR>1 {
        split($4, local_addr, ":");
        split($5, remote_addr, ":");
        local_port = local_addr[length(local_addr)];
        remote_port = remote_addr[length(remote_addr)];
        print $1","$4","local_port","$5","remote_port","$2
    }' || netstat -tuln | awk 'NR>2 {print $1","$4","$4","$5","$5","$6}'
} > "$outdir/network_connections.csv"

# 9. System Security Parameters
{
    echo "parameter,current_value,file_value,security_recommendation"

    security_params=("net.ipv4.ip_forward" "net.ipv4.conf.all.send_redirects" "net.ipv4.conf.all.accept_redirects" "net.ipv4.conf.all.accept_source_route" "kernel.dmesg_restrict" "fs.suid_dumpable" "kernel.kptr_restrict" "kernel.yama.ptrace_scope")

    for param in "${security_params[@]}"; do
        current=$(sysctl -n "$param" 2>/dev/null || echo "N/A")

        # Check file configuration
        file_val="not_set"

        # Check main sysctl config
        if [[ -f /etc/sysctl.conf ]] && grep -q "^[[:space:]]*$param[[:space:]]*=" /etc/sysctl.conf; then
            file_val=$(grep "^[[:space:]]*$param[[:space:]]*=" /etc/sysctl.conf | tail -1 | cut -d'=' -f2 | xargs)
        else
            # Check sysctl.d directory files
            if [[ -d /etc/sysctl.d ]]; then
                while IFS= read -r -d '' conf_file; do
                    if grep -q "^[[:space:]]*$param[[:space:]]*=" "$conf_file"; then
                        file_val=$(grep "^[[:space:]]*$param[[:space:]]*=" "$conf_file" | tail -1 | cut -d'=' -f2 | xargs)
                        break
                    fi
                done < <(find /etc/sysctl.d -name "*.conf" -type f -print0 2>/dev/null)
            fi
        fi

        # Security recommendations
        case "$param" in
            "net.ipv4.ip_forward") rec="Should be 0 unless routing required" ;;
            "net.ipv4.conf.all.send_redirects") rec="Should be 0" ;;
            "net.ipv4.conf.all.accept_redirects") rec="Should be 0" ;;
            "net.ipv4.conf.all.accept_source_route") rec="Should be 0" ;;
            "kernel.dmesg_restrict") rec="Should be 1" ;;
            "fs.suid_dumpable") rec="Should be 0" ;;
            "kernel.kptr_restrict") rec="Should be 1 or 2" ;;
            "kernel.yama.ptrace_scope") rec="Should be 1 or higher" ;;
        esac

        echo "$param,$current,$file_val,$rec"
    done
} > "$outdir/security_parameters.csv"

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

    # System cron directories
    for crondir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        if [[ -d "$crondir" ]]; then
            find "$crondir" -type f | while IFS= read -r file; do
                echo "$(basename "$crondir"),root,$crondir,$(basename "$file"),system"
            done
        fi
    done

    # Systemd timers
    if command -v systemctl >/dev/null 2>&1; then
        while IFS= read -r next left _ _ unit activates; do
            if [[ "$unit" != "NEXT" && "$unit" != "n/a" ]]; then
                schedule="$next $left"
                echo "systemd,root,$schedule,$activates,systemd-timer"
            fi
        done < <(systemctl list-timers --no-pager --no-legend)
    fi
} > "$outdir/scheduled_tasks.csv"

# 11. File System and Mounts
{
    echo "filesystem,mount_point,type,options,security_concern"
    while IFS= read -r device _ mount _ fstype options; do
        concern="OK"
        case "$options" in
            *nosuid*) ;;
            *) concern="INFO: SUID allowed" ;;
        esac
        case "$mount" in
            "/tmp"|"/var/tmp")
                [[ "$options" != *nosuid* ]] && concern="MEDIUM: /tmp without nosuid"
                [[ "$options" != *noexec* ]] && concern="MEDIUM: /tmp without noexec"
                ;;
            "/dev/shm")
                [[ "$options" != *nosuid* ]] && concern="MEDIUM: /dev/shm without nosuid"
                [[ "$options" != *noexec* ]] && concern="HIGH: /dev/shm without noexec"
                ;;
        esac
        echo "$device,$mount,$fstype,$options,$concern"
    done < <(mount)
} > "$outdir/filesystem_mounts.csv"

# 12. Login Security
# Failed login attempts
if [[ -f /var/log/auth.log ]]; then
    grep "Failed password" /var/log/auth.log | tail -50 > "$outdir/failed_logins.txt" 2>/dev/null
    grep "authentication failure" /var/log/auth.log | tail -50 > "$outdir/auth_failures.txt" 2>/dev/null
fi

# Successful logins
last -n 30 > "$outdir/successful_logins.txt" 2>/dev/null

# Currently logged users
{
    echo "user,tty,from,login_time,idle,what"
    w | tail -n +3 | awk '{print $1","$2","$3","$4" "$5","$6","$8}'
} > "$outdir/current_users.csv"

# 13. Ubuntu-specific Security Features
# Snap packages
if command -v snap >/dev/null 2>&1; then
    {
        echo "snap_name,version,developer,status,confinement"
        snap list | tail -n +2 | while IFS= read -r name version rev tracking publisher notes; do
            confinement=$(snap info "$name" 2>/dev/null | grep "confinement:" | awk '{print $2}')
            echo "$name,$version,$publisher,installed,$confinement"
        done
    } > "$outdir/snap_packages.csv" 2>/dev/null
fi

# Ubuntu Security Updates
if [[ -f /etc/update-manager/release-upgrades ]]; then
    cp /etc/update-manager/release-upgrades "$outdir/ubuntu_release_upgrades.txt"
fi

# Unattended upgrades configuration
if [[ -f /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
    cp /etc/apt/apt.conf.d/50unattended-upgrades "$outdir/unattended_upgrades_config.txt"
fi

# 14. Generate Summary Report
user_count=$(tail -n +2 "$outdir/linux_users.csv" 2>/dev/null | wc -l)
admin_count=$(tail -n +2 "$outdir/privileged_users.csv" 2>/dev/null | wc -l)
service_count=$(tail -n +2 "$outdir/running_services.csv" 2>/dev/null | wc -l)
package_count=$(tail -n +2 "$outdir/installed_packages.csv" 2>/dev/null | wc -l)
ufw_status=$(grep -o "Status: [a-z]*" "$outdir/ufw_status.txt" 2>/dev/null | cut -d' ' -f2 || echo "Unknown")
apparmor_status=$(aa-status --enabled 2>/dev/null | wc -l || echo "0")

{
    echo "Ubuntu 16.04-18.04 Security Audit Summary"
    echo "========================================="
    echo "Server: $hostname"
    echo "Date: $date"
    echo "OS: $(lsb_release -d 2>/dev/null | cut -f2 || echo 'Unknown')"
    echo "Kernel: $(uname -r)"
    echo "UFW Status: $ufw_status"
    echo "AppArmor Profiles: $apparmor_status"
    echo ""
    echo "Users: $user_count"
    echo "Privileged Users: $admin_count"
    echo "Running Services: $service_count"
    echo "Installed Packages: $package_count"
    echo ""
    echo "Files generated in: $outdir"
} > "$outdir/AUDIT_SUMMARY.txt"

echo "Ubuntu 16.04-18.04 audit completed"
echo "Files saved to: $outdir"