#!/bin/bash
# RHEL 8/9 Audit Script - Bash
# Target: Red Hat Enterprise Linux 8/9
# Functions: dnf updates, firewall-cmd, SELinux, systemd services

# Initialize variables
hostname=$(hostname)
os="RHEL8_9"
date=$(date +%F_%H-%M-%S)
outdir="/tmp/${hostname}_${os}_${date}"

# Create output directory
mkdir -p "$outdir"

echo "Starting RHEL 8/9 audit - $date"
echo "Output directory: $outdir"

# 1. System Information
{
    echo "hostname,os_release,kernel,architecture,uptime"
    os_release=$(cat /etc/redhat-release 2>/dev/null | tr ',' ' ')
    uptime_info=$(uptime | awk '{print $3,$4}' | sed 's/,//')
    echo "$hostname,$os_release,$(uname -r),$(uname -m),$uptime_info"
} > "$outdir/system_info.csv"

# Detailed system info
cp /etc/redhat-release "$outdir/os_version.txt" 2>/dev/null
cp /etc/os-release "$outdir/os_release.txt" 2>/dev/null
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

# System users
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

    # Wheel group members
    if getent group wheel >/dev/null 2>&1; then
        while IFS= read -r user; do
            [[ -n "$user" ]] && echo "wheel,$user,group"
        done < <(getent group wheel | cut -d: -f4 | tr ',' '\n')
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

# 3. Package Management with DNF
if command -v dnf >/dev/null 2>&1; then
    # Security updates
    dnf updateinfo list security > "$outdir/security_updates.txt" 2>/dev/null

    # All available updates
    dnf check-update > "$outdir/available_updates.txt" 2>/dev/null

    # Recently installed packages
    dnf history list | head -20 > "$outdir/dnf_history.txt" 2>/dev/null

    # Installed packages
    {
        echo "package_name,version,architecture,repository,install_date"
        rpm -qa --queryformat "%{NAME},%{VERSION}-%{RELEASE},%{ARCH},%{VENDOR},%{INSTALLTIME:date}\n" | sort
    } > "$outdir/installed_packages.csv"

    # Enabled repositories
    dnf repolist enabled > "$outdir/enabled_repos.txt" 2>/dev/null

    # Package groups
    dnf group list installed > "$outdir/installed_groups.txt" 2>/dev/null
else
    echo "dnf not available" > "$outdir/package_manager_error.txt"
fi

# 4. Systemd Services
{
    echo "service_name,load_state,active_state,sub_state,enabled_state,preset"
    while IFS= read -r unit state preset; do
        if [[ "$unit" == *.service ]]; then
            service_name="${unit%.service}"
            load_state=$(systemctl show "$unit" --property=LoadState --value 2>/dev/null)
            active_state=$(systemctl show "$unit" --property=ActiveState --value 2>/dev/null)
            sub_state=$(systemctl show "$unit" --property=SubState --value 2>/dev/null)
            echo "$service_name,$load_state,$active_state,$sub_state,$state,$preset"
        fi
    done < <(systemctl list-unit-files --type=service --no-pager --no-legend)
} > "$outdir/services.csv"

# Running services only
{
    echo "service_name,active_state,main_pid,memory_usage"
    while IFS= read -r unit _ active _ _; do
        service_name="${unit%.service}"
        main_pid=$(systemctl show "$unit" --property=MainPID --value 2>/dev/null)
        memory=$(systemctl show "$unit" --property=MemoryCurrent --value 2>/dev/null)
        echo "$service_name,$active,$main_pid,$memory"
    done < <(systemctl list-units --type=service --state=running --no-pager --no-legend)
} > "$outdir/running_services.csv"

# Critical services security check
{
    echo "service,status,security_risk,recommendation"
    critical_services=("telnet.socket" "rsh.socket" "rlogin.socket" "tftp.socket" "finger.socket")

    for svc in "${critical_services[@]}"; do
        if systemctl list-unit-files "$svc" >/dev/null 2>&1; then
            status=$(systemctl is-enabled "$svc" 2>/dev/null || echo "not-found")
            active=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
            if [[ "$status" = "enabled" ]] || [[ "$active" = "active" ]]; then
                echo "$svc,$status-$active,HIGH,Disable insecure service"
            else
                echo "$svc,$status-$active,OK,Service properly disabled"
            fi
        else
            echo "$svc,not-installed,OK,Service not present"
        fi
    done
} > "$outdir/critical_services.csv"

# 5. Firewall Configuration (firewalld)
if command -v firewall-cmd >/dev/null 2>&1; then
    # Check if firewalld is running
    if systemctl is-active firewalld >/dev/null 2>&1; then
        # General firewall status
        firewall-cmd --state > "$outdir/firewall_state.txt" 2>/dev/null

        # All zones configuration
        firewall-cmd --list-all > "$outdir/firewall_config.txt" 2>/dev/null
        firewall-cmd --list-all-zones > "$outdir/firewall_all_zones.txt" 2>/dev/null

        # Default zone
        firewall-cmd --get-default-zone > "$outdir/firewall_default_zone.txt" 2>/dev/null

        # Active zones
        firewall-cmd --get-active-zones > "$outdir/firewall_active_zones.txt" 2>/dev/null

        # Services and ports
        {
            echo "zone,type,item"
            firewall-cmd --list-all-zones | awk '
            /^[^ ]/ { zone = $1 }
            /services:/ {
                gsub(/services: /, "");
                for(i=1; i<=NF; i++) if($i!="") print zone",service,"$i
            }
            /ports:/ {
                gsub(/ports: /, "");
                for(i=1; i<=NF; i++) if($i!="") print zone",port,"$i
            }'
        } > "$outdir/firewall_rules.csv" 2>/dev/null

        # Rich rules
        firewall-cmd --list-rich-rules > "$outdir/firewall_rich_rules.txt" 2>/dev/null
    else
        echo "firewalld is not running" > "$outdir/firewall_disabled.txt"
    fi
else
    echo "firewall-cmd not available" > "$outdir/firewall_error.txt"
fi

# 6. SELinux Configuration
if command -v getenforce >/dev/null 2>&1; then
    # SELinux status
    getenforce > "$outdir/selinux_status.txt"
    sestatus > "$outdir/selinux_detailed.txt" 2>/dev/null

    # SELinux configuration
    if [[ -f /etc/selinux/config ]]; then
        cp /etc/selinux/config "$outdir/selinux_config.txt"
    fi

    # SELinux booleans
    {
        echo "boolean,state,default,description"
        while IFS= read -r bool state; do
            default=$(semanage boolean -l 2>/dev/null | grep "^$bool " | awk '{print $3}' || echo "unknown")
            desc=$(semanage boolean -l 2>/dev/null | grep "^$bool " | cut -d'(' -f2 | cut -d')' -f1 || echo "no description")
            echo "$bool,$state,$default,$desc"
        done < <(getsebool -a)
    } > "$outdir/selinux_booleans.csv" 2>/dev/null

    # SELinux contexts for critical directories
    {
        echo "path,context,type"
        critical_paths=("/etc" "/var/log" "/home" "/tmp" "/var/tmp")
        for path in "${critical_paths[@]}"; do
            if [[ -d "$path" ]]; then
                context=$(ls -ldZ "$path" 2>/dev/null | awk '{print $4}')
                context_type=$(echo "$context" | cut -d: -f3)
                echo "$path,$context,$context_type"
            fi
        done
    } > "$outdir/selinux_contexts.csv"

    # Recent SELinux denials
    if command -v ausearch >/dev/null 2>&1; then
        ausearch -m avc -ts recent 2>/dev/null | head -50 > "$outdir/selinux_denials.txt"
    fi

    # SELinux violations summary
    if command -v sealert >/dev/null 2>&1; then
        sealert -a /var/log/audit/audit.log 2>/dev/null | head -100 > "$outdir/selinux_alerts.txt"
    fi
else
    echo "SELinux tools not available" > "$outdir/selinux_error.txt"
fi

# 7. SSH Configuration
if [[ -f /etc/ssh/sshd_config ]]; then
    # Full SSH config
    cp /etc/ssh/sshd_config "$outdir/sshd_config.txt"

    # Key security settings
    {
        echo "setting,value,security_level"

        # Extract key settings
        permit_root=$(grep -i "^[[:space:]]*PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}' | tail -1)
        password_auth=$(grep -i "^[[:space:]]*PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}' | tail -1)
        pubkey_auth=$(grep -i "^[[:space:]]*PubkeyAuthentication" /etc/ssh/sshd_config | awk '{print $2}' | tail -1)
        protocol=$(grep -i "^[[:space:]]*Protocol" /etc/ssh/sshd_config | awk '{print $2}' | tail -1)
        port=$(grep -i "^[[:space:]]*Port" /etc/ssh/sshd_config | awk '{print $2}' | tail -1)

        # Evaluate security levels
        [[ "$permit_root" = "no" ]] && root_risk="OK" || root_risk="HIGH"
        [[ "$password_auth" = "no" ]] && pass_risk="OK" || pass_risk="MEDIUM"
        [[ "$pubkey_auth" = "yes" ]] && key_risk="OK" || key_risk="MEDIUM"
        [[ "$port" != "22" ]] && port_risk="OK" || port_risk="INFO"

        echo "PermitRootLogin,${permit_root:-default},$root_risk"
        echo "PasswordAuthentication,${password_auth:-default},$pass_risk"
        echo "PubkeyAuthentication,${pubkey_auth:-default},$key_risk"
        echo "Port,${port:-22},$port_risk"
        echo "Protocol,${protocol:-2},OK"
    } > "$outdir/ssh_security_config.csv"

    # SSH service status
    systemctl status sshd > "$outdir/ssh_service_status.txt" 2>/dev/null
else
    echo "SSH config not found" > "$outdir/ssh_error.txt"
fi

# 8. Network Configuration
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

# Network connections
{
    echo "protocol,local_address,local_port,remote_address,remote_port,state,process"
    ss -tuln | awk 'NR>1 {
        split($4, local_addr, ":");
        split($5, remote_addr, ":");
        local_port = local_addr[length(local_addr)];
        remote_port = remote_addr[length(remote_addr)];
        print $1","$4","local_port","$5","remote_port","$2",N/A"
    }'
} > "$outdir/network_connections.csv"

# Routing table
ip route show > "$outdir/routing_table.txt"

# 9. System Security Parameters
{
    echo "parameter,current_value,file_value,security_recommendation"

    # Important kernel parameters
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

# 10. File System and Mounts
{
    echo "filesystem,mount_point,type,options,security_concern"
    while IFS= read -r device _ mount _ fstype options; do
        # Check for security concerns
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
        esac
        echo "$device,$mount,$fstype,$options,$concern"
    done < <(mount)
} > "$outdir/filesystem_mounts.csv"

# 11. Cron and Scheduled Tasks
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
        if [[ "$unit" != "NEXT" ]]; then
            schedule="$next $left"
            echo "systemd,root,$schedule,$activates,systemd-timer"
        fi
    done < <(systemctl list-timers --no-pager --no-legend)
} > "$outdir/scheduled_tasks.csv"

# 12. Login Security and User Activity
# Failed logins
if [[ -f /var/log/secure ]]; then
    grep "Failed" /var/log/secure | tail -50 > "$outdir/failed_logins.txt" 2>/dev/null
fi

# Successful logins
last -n 30 > "$outdir/successful_logins.txt" 2>/dev/null

# Currently logged users
{
    echo "user,tty,from,login_time,idle,what"
    w | tail -n +3 | awk '{print $1","$2","$3","$4" "$5","$6","$8}'
} > "$outdir/current_users.csv"

# 13. Generate Summary Report
user_count=$(tail -n +2 "$outdir/linux_users.csv" 2>/dev/null | wc -l)
admin_count=$(tail -n +2 "$outdir/privileged_users.csv" 2>/dev/null | wc -l)
service_count=$(tail -n +2 "$outdir/running_services.csv" 2>/dev/null | wc -l)
package_count=$(tail -n +2 "$outdir/installed_packages.csv" 2>/dev/null | wc -l)
selinux_status=$(< "$outdir/selinux_status.txt" 2>/dev/null || echo "Unknown")
firewall_status=$(< "$outdir/firewall_state.txt" 2>/dev/null || echo "Unknown")

{
    echo "RHEL 8/9 Security Audit Summary"
    echo "==============================="
    echo "Server: $hostname"
    echo "Date: $date"
    echo "OS: $(< /etc/redhat-release 2>/dev/null || echo 'Unknown')"
    echo "Kernel: $(uname -r)"
    echo "SELinux: $selinux_status"
    echo "Firewall: $firewall_status"
    echo ""
    echo "Users: $user_count"
    echo "Privileged Users: $admin_count"
    echo "Running Services: $service_count"
    echo "Installed Packages: $package_count"
    echo ""
    echo "Files generated in: $outdir"
} > "$outdir/AUDIT_SUMMARY.txt"

echo "RHEL 8/9 audit completed"
echo "Files saved to: $outdir"