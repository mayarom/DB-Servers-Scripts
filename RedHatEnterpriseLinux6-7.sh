#!/bin/bash
# RHEL 6/7 Audit Script - Bash
# Target: Red Hat Enterprise Linux 6/7
# Functions: Updates, SSH, firewall, SELinux, users

# Initialize variables
hostname=$(hostname)
os="RHEL6_7"
date=$(date +%F_%H-%M-%S)
outdir="/tmp/${hostname}_${os}_${date}"

# Create output directory
mkdir -p "$outdir"

echo "Starting RHEL audit - $date"
echo "Output directory: $outdir"

# 1. System Information
{
    echo "hostname,os_release,kernel,architecture,uptime"
    echo "$hostname,$(cat /etc/redhat-release 2>/dev/null | tr ',' ' '),$(uname -r),$(uname -m),$(uptime | awk '{print $3,$4}' | sed 's/,//')"
} > "$outdir/system_info.csv"

# Get detailed system info
cat /etc/redhat-release > "$outdir/os_version.txt" 2>/dev/null
uname -a > "$outdir/kernel_info.txt"
uptime > "$outdir/uptime.txt"
cat /proc/meminfo > "$outdir/memory_info.txt"
cat /proc/cpuinfo > "$outdir/cpu_info.txt"

# 2. Users and Groups
{
    echo "username,uid,gid,home_dir,shell,gecos"
    getent passwd | awk -F: '$3 >= 1000 && $3 != 65534 {
        gsub(/,/, ";", $5);
        print $1","$3","$4","$6","$7","$5
    }'
} > "$outdir/linux_users.csv"

# All users (including system users)
{
    echo "username,uid,gid,home_dir,shell,gecos"
    getent passwd | awk -F: '{
        gsub(/,/, ";", $5);
        print $1","$3","$4","$6","$7","$5
    }'
} > "$outdir/all_users.csv"

# Groups
{
    echo "groupname,gid,members"
    getent group | awk -F: '{
        gsub(/,/, ";", $4);
        print $1","$3","$4
    }'
} > "$outdir/groups.csv"

# Root and sudo users
{
    echo "type,username"
    # Root user
    echo "root,root"

    # Sudo group members
    if getent group sudo >/dev/null 2>&1; then
        getent group sudo | cut -d: -f4 | tr ',' '\n' | while read user; do
            [ -n "$user" ] && echo "sudo,$user"
        done
    fi

    # Wheel group members (RHEL default)
    if getent group wheel >/dev/null 2>&1; then
        getent group wheel | cut -d: -f4 | tr ',' '\n' | while read user; do
            [ -n "$user" ] && echo "wheel,$user"
        done
    fi

    # Check sudoers file for additional users
    if [ -r /etc/sudoers ]; then
        grep -E "^[^#]*ALL.*ALL" /etc/sudoers | awk '{print "sudoers,"$1}' | grep -v "^sudoers,%"
    fi
} > "$outdir/privileged_users.csv"

# 3. Package Updates and Security Patches
if command -v yum >/dev/null 2>&1; then
    # Available updates
    yum check-update > "$outdir/available_updates.txt" 2>/dev/null

    # Security updates
    yum updateinfo list security > "$outdir/security_updates.txt" 2>/dev/null

    # Recently installed packages
    rpm -qa --last | head -50 > "$outdir/recent_packages.txt"

    # All installed packages
    {
        echo "package_name,version,architecture,install_date"
        rpm -qa --queryformat "%{NAME},%{VERSION}-%{RELEASE},%{ARCH},%{INSTALLTIME:date}\n" | sort
    } > "$outdir/installed_packages.csv"
else
    echo "yum not available" > "$outdir/package_manager_error.txt"
fi

# 4. SSH Configuration
if [ -f /etc/ssh/sshd_config ]; then
    # Copy full SSH config
    cp /etc/ssh/sshd_config "$outdir/sshd_config_full.txt"

    # Extract key security settings
    {
        echo "setting,value"
        grep -Ei '^[^#]*PermitRootLogin' /etc/ssh/sshd_config | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]\+/,/'
        grep -Ei '^[^#]*PasswordAuthentication' /etc/ssh/sshd_config | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]\+/,/'
        grep -Ei '^[^#]*PubkeyAuthentication' /etc/ssh/sshd_config | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]\+/,/'
        grep -Ei '^[^#]*Protocol' /etc/ssh/sshd_config | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]\+/,/'
        grep -Ei '^[^#]*Port' /etc/ssh/sshd_config | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]\+/,/'
        grep -Ei '^[^#]*MaxAuthTries' /etc/ssh/sshd_config | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]\+/,/'
        grep -Ei '^[^#]*ClientAliveInterval' /etc/ssh/sshd_config | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]\+/,/'
        grep -Ei '^[^#]*AllowUsers' /etc/ssh/sshd_config | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]\+/,/'
        grep -Ei '^[^#]*DenyUsers' /etc/ssh/sshd_config | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]\+/,/'
    } | grep -v "^setting,value$" | sed '1i setting,value' > "$outdir/ssh_security_config.csv"

    # SSH service status
    if command -v systemctl >/dev/null 2>&1; then
        systemctl status sshd > "$outdir/ssh_service_status.txt" 2>/dev/null
    elif command -v service >/dev/null 2>&1; then
        service sshd status > "$outdir/ssh_service_status.txt" 2>/dev/null
    fi
else
    echo "SSH config file not found" > "$outdir/ssh_config_error.txt"
fi

# 5. Firewall Configuration
# iptables (RHEL 6/7)
if command -v iptables >/dev/null 2>&1; then
    iptables -L -n > "$outdir/iptables_rules.txt" 2>/dev/null
    iptables -L -n -v > "$outdir/iptables_verbose.txt" 2>/dev/null
    iptables -t nat -L -n > "$outdir/iptables_nat.txt" 2>/dev/null
fi

# firewalld (RHEL 7)
if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --list-all > "$outdir/firewalld_config.txt" 2>/dev/null
    firewall-cmd --list-services > "$outdir/firewalld_services.txt" 2>/dev/null
    firewall-cmd --list-ports > "$outdir/firewalld_ports.txt" 2>/dev/null

    # Check if firewalld is running
    if systemctl is-active firewalld >/dev/null 2>&1; then
        echo "enabled" > "$outdir/firewalld_status.txt"
    else
        echo "disabled" > "$outdir/firewalld_status.txt"
    fi
fi

# 6. SELinux Status
if command -v getenforce >/dev/null 2>&1; then
    getenforce > "$outdir/selinux_status.txt"
    sestatus > "$outdir/selinux_detailed.txt" 2>/dev/null

    # SELinux configuration
    if [ -f /etc/selinux/config ]; then
        cp /etc/selinux/config "$outdir/selinux_config.txt"
    fi

    # SELinux violations (if auditd is running)
    if command -v ausearch >/dev/null 2>&1; then
        ausearch -m avc -ts recent 2>/dev/null | head -100 > "$outdir/selinux_violations.txt"
    fi
else
    echo "SELinux not available" > "$outdir/selinux_error.txt"
fi

# 7. Services
{
    echo "service_name,status,enabled"
    if command -v systemctl >/dev/null 2>&1; then
        # RHEL 7 systemd
        systemctl list-units --type=service --no-pager --no-legend | while read service load active sub description; do
            enabled=$(systemctl is-enabled "$service" 2>/dev/null || echo "unknown")
            echo "$service,$active,$enabled"
        done
    else
        # RHEL 6 SysV
        chkconfig --list 2>/dev/null | while read service levels; do
            if echo "$levels" | grep -q "3:on"; then
                enabled="enabled"
            else
                enabled="disabled"
            fi

            if service "$service" status >/dev/null 2>&1; then
                status="running"
            else
                status="stopped"
            fi
            echo "$service,$status,$enabled"
        done
    fi
} > "$outdir/services.csv"

# Critical services check
{
    echo "service,status,security_concern"
    critical_services="telnet rsh rlogin tftp finger chargen daytime echo discard time"

    for svc in $critical_services; do
        if command -v systemctl >/dev/null 2>&1; then
            if systemctl is-active "$svc" >/dev/null 2>&1; then
                echo "$svc,active,HIGH"
            else
                echo "$svc,inactive,OK"
            fi
        else
            if service "$svc" status >/dev/null 2>&1; then
                echo "$svc,running,HIGH"
            else
                echo "$svc,stopped,OK"
            fi
        fi
    done
} > "$outdir/critical_services.csv"

# 8. Network Configuration
{
    echo "interface,ip_address,netmask,status"
    ip addr show 2>/dev/null | awk '
    /^[0-9]+:/ {
        interface = $2;
        gsub(/:/, "", interface)
    }
    /inet / {
        split($2, addr, "/")
        print interface","addr[1]","$2","$8
    }' 2>/dev/null
} > "$outdir/network_interfaces.csv"

# Network connections
{
    echo "protocol,local_address,local_port,remote_address,remote_port,state"
    netstat -tuln 2>/dev/null | awk 'NR>2 {print $1","$4","$4","$5","$5","$6}' | sed 's/://g'
} > "$outdir/network_connections.csv"

# Routing table
ip route show > "$outdir/routing_table.txt" 2>/dev/null || route -n > "$outdir/routing_table.txt" 2>/dev/null

# 9. File Permissions on Critical Files
{
    echo "file_path,permissions,owner,group,security_risk"
    critical_files="/etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/ssh/sshd_config /etc/crontab"

    for file in $critical_files; do
        if [ -f "$file" ]; then
            perms=$(stat -c "%a" "$file" 2>/dev/null)
            owner=$(stat -c "%U" "$file" 2>/dev/null)
            group=$(stat -c "%G" "$file" 2>/dev/null)

            # Check for security risks
            risk="OK"
            case "$file" in
                "/etc/shadow"|"/etc/gshadow")
                    [ "$perms" != "000" ] && [ "$perms" != "400" ] && [ "$perms" != "600" ] && risk="HIGH"
                    ;;
                "/etc/passwd"|"/etc/group")
                    [ "$perms" -gt "644" ] && risk="MEDIUM"
                    ;;
                "/etc/sudoers")
                    [ "$perms" != "440" ] && [ "$perms" != "400" ] && risk="HIGH"
                    ;;
                "/etc/ssh/sshd_config")
                    [ "$perms" -gt "644" ] && risk="MEDIUM"
                    ;;
            esac

            echo "$file,$perms,$owner,$group,$risk"
        fi
    done
} > "$outdir/critical_file_permissions.csv"

# 10. Cron Jobs
{
    echo "type,user,schedule,command"

    # System crontab
    if [ -f /etc/crontab ]; then
        grep -v "^#" /etc/crontab | grep -v "^$" | while read line; do
            echo "system,root,$(echo "$line" | cut -d' ' -f1-5),$(echo "$line" | cut -d' ' -f6-)"
        done
    fi

    # Cron directories
    for crondir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        if [ -d "$crondir" ]; then
            ls -1 "$crondir" 2>/dev/null | while read file; do
                echo "$(basename $crondir),root,$crondir,$file"
            done
        fi
    done

    # User crontabs
    for user in $(cut -d: -f1 /etc/passwd); do
        if crontab -u "$user" -l >/dev/null 2>&1; then
            crontab -u "$user" -l 2>/dev/null | grep -v "^#" | grep -v "^$" | while read line; do
                echo "user,$user,$(echo "$line" | cut -d' ' -f1-5),$(echo "$line" | cut -d' ' -f6-)"
            done
        fi
    done
} > "$outdir/cron_jobs.csv"

# 11. Login Security
# Last logins
last -n 50 > "$outdir/last_logins.txt" 2>/dev/null

# Failed login attempts
if [ -f /var/log/secure ]; then
    grep "Failed password" /var/log/secure | tail -100 > "$outdir/failed_logins.txt" 2>/dev/null
fi

# Currently logged in users
{
    echo "user,tty,login_time,idle_time,what"
    w | tail -n +3 | awk '{print $1","$2","$3" "$4","$5","$8}'
} > "$outdir/current_users.csv"

# 12. System Security Settings
{
    echo "parameter,value,file"

    # Kernel parameters
    sysctl_files="/etc/sysctl.conf /etc/sysctl.d/*.conf"
    for file in $sysctl_files; do
        if [ -f "$file" ]; then
            grep -v "^#" "$file" | grep -v "^$" | while read line; do
                param=$(echo "$line" | cut -d'=' -f1 | xargs)
                value=$(echo "$line" | cut -d'=' -f2- | xargs)
                echo "$param,$value,$file"
            done
        fi
    done

    # Important runtime values
    important_sysctls="net.ipv4.ip_forward net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_redirects kernel.dmesg_restrict fs.suid_dumpable"
    for param in $important_sysctls; do
        value=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
        echo "$param,$value,runtime"
    done
} > "$outdir/security_parameters.csv"

# 13. Installed Security Tools
{
    echo "tool,status,version"
    security_tools="aide tripwire chkrootkit rkhunter clamav fail2ban denyhosts"

    for tool in $security_tools; do
        if command -v "$tool" >/dev/null 2>&1; then
            version=$($tool --version 2>/dev/null | head -1 | cut -d' ' -f3 || echo "unknown")
            echo "$tool,installed,$version"
        else
            echo "$tool,not_installed,N/A"
        fi
    done
} > "$outdir/security_tools.csv"

# 14. Generate Summary Report
user_count=$(wc -l < "$outdir/linux_users.csv" 2>/dev/null | xargs)
admin_count=$(wc -l < "$outdir/privileged_users.csv" 2>/dev/null | xargs)
package_count=$(wc -l < "$outdir/installed_packages.csv" 2>/dev/null | xargs)
service_count=$(wc -l < "$outdir/services.csv" 2>/dev/null | xargs)
selinux_status=$(cat "$outdir/selinux_status.txt" 2>/dev/null || echo "Unknown")

{
    echo "RHEL Security Audit Summary"
    echo "=========================="
    echo "Server: $hostname"
    echo "Date: $date"
    echo "OS: $(cat /etc/redhat-release 2>/dev/null || echo 'Unknown')"
    echo "Kernel: $(uname -r)"
    echo "SELinux: $selinux_status"
    echo ""
    echo "Users: $user_count"
    echo "Privileged Users: $admin_count"
    echo "Installed Packages: $package_count"
    echo "Services: $service_count"
    echo ""
    echo "Files generated in: $outdir"
} > "$outdir/AUDIT_SUMMARY.txt"

echo "RHEL audit completed"
echo "Files saved to: $outdir"