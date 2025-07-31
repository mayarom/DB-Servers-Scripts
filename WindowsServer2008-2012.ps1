# Windows Server Audit Script - PowerShell
# Target: Windows Server 2008-2012
# Functions: Users, passwords, groups, updates, firewall, RDP

param(
    [string]$ComputerName = $env:COMPUTERNAME
)

# Initialize variables
$hostname = $env:COMPUTERNAME
$version = "WinServer"
$date = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outDir = "C:\Audit\$hostname`_$version`_$date"

# Create output directory
try {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    Write-Host "Starting Windows Server audit - $date"
    Write-Host "Output directory: $outDir"
} catch {
    Write-Host "Failed to create directory: $($_.Exception.Message)"
    exit 1
}

# 1. System Information
$systemInfo = Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, ServicePackMajorVersion, InstallDate, LastBootUpTime, TotalVisibleMemorySize
$systemInfo | Export-Csv -Path "$outDir\system_info.csv" -NoTypeInformation

$computerInfo = Get-WmiObject -Class Win32_ComputerSystem | Select-Object Name, Domain, Workgroup, TotalPhysicalMemory, NumberOfProcessors
$computerInfo | Export-Csv -Path "$outDir\computer_info.csv" -NoTypeInformation

# 2. Local Users
try {
    $localUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" | Select-Object Name, FullName, Description, Disabled, Lockout, PasswordRequired, PasswordChangeable, PasswordExpires, SID
    $localUsers | Export-Csv -Path "$outDir\local_users.csv" -NoTypeInformation
} catch {
    net user | Out-String | Out-File "$outDir\local_users_fallback.txt"
}

# 3. Local Groups
try {
    $localGroups = Get-WmiObject -Class Win32_Group -Filter "LocalAccount=True" | Select-Object Name, Description, SID
    $localGroups | Export-Csv -Path "$outDir\local_groups.csv" -NoTypeInformation
} catch {
    net localgroup | Out-File "$outDir\local_groups_fallback.txt"
}

# 4. Administrators Group Members
$adminMembers = @()
try {
    $adminGroup = ([ADSI]"WinNT://$ComputerName/Administrators,group")
    $adminGroup.Members() | ForEach-Object {
        $member = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
        $class = $_.GetType().InvokeMember("Class", 'GetProperty', $null, $_, $null)
        $memberObj = New-Object PSObject
        $memberObj | Add-Member -MemberType NoteProperty -Name "Name" -Value $member
        $memberObj | Add-Member -MemberType NoteProperty -Name "Type" -Value $class
        $adminMembers += $memberObj
    }
    if ($adminMembers.Count -gt 0) {
        $adminMembers | Export-Csv -Path "$outDir\administrators.csv" -NoTypeInformation
    }
} catch {
    net localgroup administrators | Out-File "$outDir\administrators_fallback.txt"
}

# 5. Password Policy
try {
    $passwordPolicy = net accounts | Out-String
    $passwordPolicy | Out-File "$outDir\password_policy.txt"

    $policyLines = $passwordPolicy -split "`n" | Where-Object { $_ -match ":" }
    $policyData = @()
    foreach ($line in $policyLines) {
        if ($line -match "^(.+?):\s*(.+)$") {
            $policyObj = New-Object PSObject
            $policyObj | Add-Member -MemberType NoteProperty -Name "Setting" -Value $matches[1].Trim()
            $policyObj | Add-Member -MemberType NoteProperty -Name "Value" -Value $matches[2].Trim()
            $policyData += $policyObj
        }
    }
    if ($policyData.Count -gt 0) {
        $policyData | Export-Csv -Path "$outDir\password_policy.csv" -NoTypeInformation
    }
} catch {
    Write-Host "Failed to get password policy"
}

# 6. Installed Updates/Hotfixes
try {
    $hotfixes = Get-WmiObject -Class Win32_QuickFixEngineering | Select-Object HotFixID, Description, InstalledBy, InstalledOn | Sort-Object InstalledOn -Descending
    $hotfixes | Export-Csv -Path "$outDir\hotfixes.csv" -NoTypeInformation
} catch {
    try {
        wmic qfe list brief /format:csv | Out-File "$outDir\hotfixes_wmic.csv"
    } catch {
        Write-Host "Failed to get hotfix information"
    }
}

# 7. Windows Update Configuration
try {
    $updateConfig = @()
    $auKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    )

    foreach ($keyPath in $auKeys) {
        if (Test-Path $keyPath) {
            $key = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
            if ($key) {
                foreach ($property in $key.PSObject.Properties) {
                    if ($property.Name -notlike "PS*") {
                        $configObj = New-Object PSObject
                        $configObj | Add-Member -MemberType NoteProperty -Name "Key" -Value $keyPath
                        $configObj | Add-Member -MemberType NoteProperty -Name "Setting" -Value $property.Name
                        $configObj | Add-Member -MemberType NoteProperty -Name "Value" -Value $property.Value
                        $updateConfig += $configObj
                    }
                }
            }
        }
    }
    if ($updateConfig.Count -gt 0) {
        $updateConfig | Export-Csv -Path "$outDir\windows_update_config.csv" -NoTypeInformation
    }
} catch {
    Write-Host "Failed to get Windows Update configuration"
}

# 8. Firewall Configuration
try {
    $firewallProfiles = @()
    $profileNames = @("domainprofile", "privateprofile", "publicprofile")

    foreach ($profileName in $profileNames) {
        $profileInfo = netsh advfirewall show $profileName | Out-String
        $profileObj = New-Object PSObject
        $profileObj | Add-Member -MemberType NoteProperty -Name "Profile" -Value $profileName
        $profileObj | Add-Member -MemberType NoteProperty -Name "Configuration" -Value $profileInfo
        $firewallProfiles += $profileObj
    }

    netsh advfirewall show allprofiles | Out-File "$outDir\firewall_detailed.txt"
    netsh advfirewall firewall show rule name=all | Out-File "$outDir\firewall_rules.txt"

    if ($firewallProfiles.Count -gt 0) {
        $firewallProfiles | Export-Csv -Path "$outDir\firewall_profiles.csv" -NoTypeInformation
    }
} catch {
    Write-Host "Failed to get firewall configuration"
}

# 9. RDP Configuration
try {
    $rdpConfig = @()

    $rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    if ($rdpEnabled) {
        $rdpObj = New-Object PSObject
        $rdpObj | Add-Member -MemberType NoteProperty -Name "Setting" -Value "RDP Enabled"
        $rdpObj | Add-Member -MemberType NoteProperty -Name "Value" -Value $(if ($rdpEnabled.fDenyTSConnections -eq 0) { "Yes" } else { "No" })
        $rdpConfig += $rdpObj
    }

    $rdpPort = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -ErrorAction SilentlyContinue
    if ($rdpPort) {
        $portObj = New-Object PSObject
        $portObj | Add-Member -MemberType NoteProperty -Name "Setting" -Value "RDP Port"
        $portObj | Add-Member -MemberType NoteProperty -Name "Value" -Value $rdpPort.PortNumber
        $rdpConfig += $portObj
    }

    $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
    if ($nla) {
        $nlaObj = New-Object PSObject
        $nlaObj | Add-Member -MemberType NoteProperty -Name "Setting" -Value "Network Level Authentication"
        $nlaObj | Add-Member -MemberType NoteProperty -Name "Value" -Value $(if ($nla.UserAuthentication -eq 1) { "Enabled" } else { "Disabled" })
        $rdpConfig += $nlaObj
    }

    if ($rdpConfig.Count -gt 0) {
        $rdpConfig | Export-Csv -Path "$outDir\rdp_configuration.csv" -NoTypeInformation
    }
} catch {
    Write-Host "Failed to get RDP configuration"
}

# 10. Services
try {
    $services = Get-WmiObject -Class Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName | Sort-Object Name
    $services | Export-Csv -Path "$outDir\services.csv" -NoTypeInformation

    $criticalServices = $services | Where-Object {
        $_.Name -in @("Spooler", "Themes", "BITS", "wuauserv", "WSUS", "RemoteRegistry", "Telnet", "SNMP") -or
        $_.Name -like "*SQL*" -or
        $_.Name -like "*IIS*" -or
        $_.StartName -like "*LocalSystem*"
    }
    $criticalServices | Export-Csv -Path "$outDir\critical_services.csv" -NoTypeInformation
} catch {
    Write-Host "Failed to get services information"
}

# 11. Installed Software
try {
    $software = @()
    $uninstallKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($key in $uninstallKeys) {
        Get-ItemProperty $key -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        ForEach-Object {
            $softwareObj = New-Object PSObject
            $softwareObj | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.DisplayName
            $softwareObj | Add-Member -MemberType NoteProperty -Name "Version" -Value $_.DisplayVersion
            $softwareObj | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $_.Publisher
            $softwareObj | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value $_.InstallDate
            $softwareObj | Add-Member -MemberType NoteProperty -Name "UninstallString" -Value $_.UninstallString
            $software += $softwareObj
        }
    }
    if ($software.Count -gt 0) {
        $software | Sort-Object Name | Export-Csv -Path "$outDir\installed_software.csv" -NoTypeInformation
    }
} catch {
    Write-Host "Failed to get installed software"
}

# 12. Security Settings
try {
    $securitySettings = @()

    $uacKeys = @{
        "EnableLUA" = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        "ConsentPromptBehaviorAdmin" = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        "ConsentPromptBehaviorUser" = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        "EnableSecureUIAPaths" = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    }

    foreach ($setting in $uacKeys.GetEnumerator()) {
        $value = Get-ItemProperty -Path $setting.Value -Name $setting.Key -ErrorAction SilentlyContinue
        if ($value) {
            $secObj = New-Object PSObject
            $secObj | Add-Member -MemberType NoteProperty -Name "Category" -Value "UAC"
            $secObj | Add-Member -MemberType NoteProperty -Name "Setting" -Value $setting.Key
            $secObj | Add-Member -MemberType NoteProperty -Name "Value" -Value $value.($setting.Key)
            $securitySettings += $secObj
        }
    }

    if (Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue) {
        $defenderStatus = Get-Service -Name "WinDefend"
        $defObj = New-Object PSObject
        $defObj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Windows Defender"
        $defObj | Add-Member -MemberType NoteProperty -Name "Setting" -Value "Service Status"
        $defObj | Add-Member -MemberType NoteProperty -Name "Value" -Value $defenderStatus.Status
        $securitySettings += $defObj
    }

    if ($securitySettings.Count -gt 0) {
        $securitySettings | Export-Csv -Path "$outDir\security_settings.csv" -NoTypeInformation
    }
} catch {
    Write-Host "Failed to get security settings"
}

# 13. Network Configuration
try {
    $networkAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } |
        Select-Object Description, IPAddress, SubnetMask, DefaultIPGateway, DNSServerSearchOrder, DHCPEnabled
    $networkAdapters | Export-Csv -Path "$outDir\network_adapters.csv" -NoTypeInformation

    $shares = Get-WmiObject -Class Win32_Share | Select-Object Name, Path, Description, Type
    $shares | Export-Csv -Path "$outDir\network_shares.csv" -NoTypeInformation
} catch {
    Write-Host "Failed to get network configuration"
}

# 14. Event Log Configuration
try {
    $eventLogs = @()
    $logNames = @("System", "Application", "Security")

    foreach ($logName in $logNames) {
        $log = Get-WmiObject -Class Win32_NTEventlogFile | Where-Object { $_.LogfileName -eq $logName }
        if ($log) {
            $logObj = New-Object PSObject
            $logObj | Add-Member -MemberType NoteProperty -Name "LogName" -Value $logName
            $logObj | Add-Member -MemberType NoteProperty -Name "MaxFileSize" -Value $log.MaxFileSize
            $logObj | Add-Member -MemberType NoteProperty -Name "OverwritePolicy" -Value $log.OverwritePolicy
            $logObj | Add-Member -MemberType NoteProperty -Name "NumberOfRecords" -Value $log.NumberOfRecords
            $logObj | Add-Member -MemberType NoteProperty -Name "LogFilePath" -Value $log.Name
            $eventLogs += $logObj
        }
    }
    if ($eventLogs.Count -gt 0) {
        $eventLogs | Export-Csv -Path "$outDir\event_log_config.csv" -NoTypeInformation
    }
} catch {
    Write-Host "Failed to get event log configuration"
}

# 15. Scheduled Tasks
try {
    if (Get-Command "Get-ScheduledTask" -ErrorAction SilentlyContinue) {
        $tasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, State, Author
        $tasks | Export-Csv -Path "$outDir\scheduled_tasks.csv" -NoTypeInformation
    } else {
        schtasks /query /fo csv /v | Out-File "$outDir\scheduled_tasks_schtasks.csv"
    }
} catch {
    Write-Host "Failed to get scheduled tasks"
}

# 16. Generate Summary Report
$userCount = if ($localUsers) { ($localUsers | Measure-Object).Count } else { "N/A" }
$groupCount = if ($localGroups) { ($localGroups | Measure-Object).Count } else { "N/A" }
$adminCount = if ($adminMembers) { ($adminMembers | Measure-Object).Count } else { "N/A" }
$hotfixCount = if ($hotfixes) { ($hotfixes | Measure-Object).Count } else { "N/A" }
$runningServiceCount = if ($services) { ($services | Where-Object { $_.State -eq "Running" } | Measure-Object).Count } else { "N/A" }
$softwareCount = if ($software) { ($software | Measure-Object).Count } else { "N/A" }

$summaryReport = @"
Windows Server Security Audit Summary
=====================================
Server: $hostname
Date: $date
OS Version: $($systemInfo.Caption)
Build: $($systemInfo.Version)
Domain: $($computerInfo.Domain)

Local Users: $userCount
Local Groups: $groupCount
Administrators: $adminCount
Installed Updates: $hotfixCount
Running Services: $runningServiceCount
Installed Software: $softwareCount

Files generated in: $outDir
"@

$summaryReport | Out-File -FilePath "$outDir\AUDIT_SUMMARY.txt"

Write-Host "Windows Server audit completed"
Write-Host "Files saved to: $outDir"