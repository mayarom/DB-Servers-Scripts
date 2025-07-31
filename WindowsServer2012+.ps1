<#
    Script Name: Windows Security Audit Script
    Version: 5.4
    Author: Maya Rom – Information Security Consultant

    Description:
    This script is designed for **read-only security auditing** on Windows servers and workstations.
    It **does not modify** any system configurations, settings, or files.
    The purpose is solely to collect security-relevant information for assessment and reporting.

    Intended Platforms:
    - Windows Server 2012 R2
    - Windows Server 2016
    - Windows Server 2019
    - Windows Server 2022
    - Windows 10
    - Windows 11

    Important Notes:
    - The script must be run with administrative privileges to collect complete information.
    - It is recommended to execute the script in a controlled and approved environment.
    - No changes, installations, or updates are performed by the script.

    © 2025 Maya Rom. All rights reserved.
#>

# Define global variables
[System.Collections.ArrayList]$ErrorLog = [System.Collections.ArrayList]::new()
$ErrorActionPreference = "Stop"
$serverName = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$desktopPath = [Environment]::GetFolderPath("Desktop")
$folderPath = Join-Path $desktopPath "SecurityServerResults_$serverName"
$tempFolderPath = Join-Path $env:TEMP "SecurityAudit_$timestamp"

# Define report paths
$gpoFilePath             = Join-Path $folderPath "GPO_Settings.html"
$installedSoftwarePath   = Join-Path $folderPath "Installed_Software.html"
$updateHistoryPath       = Join-Path $folderPath "Update_History.html"
$localUsersPath          = Join-Path $folderPath "Local_Users.html"
$groupMembersPath        = Join-Path $folderPath "User_Groups.html"
$systemInfoPath          = Join-Path $folderPath "System_Information.html"
$defenderConfigFilePath  = Join-Path $folderPath "Defender_Config.html"
$firewallConfigFilePath  = Join-Path $folderPath "Firewall_Settings.html"
$servicesReportPath      = Join-Path $folderPath "Services_Report.html"
$networkConnectionsPath  = Join-Path $folderPath "Network_Connections.html"
$passwordPolicyPath      = Join-Path $folderPath "Password_Policy.html"
$errorLogPath            = Join-Path $folderPath "Error_Log.html"

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).
            IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires administrator privileges. Please run PowerShell as Administrator."
    exit
}

# Create export directory
if (Test-Path $folderPath) {
    try {
        Remove-Item -Path $folderPath -Recurse -Force
        Start-Sleep -Seconds 2
    }
    catch {
        Write-Error "Unable to clean up existing directory: $_"
        exit
    }
}

# Create temp directory
if (!(Test-Path $tempFolderPath)) {
    try {
        New-Item -ItemType Directory -Path $tempFolderPath -Force | Out-Null
    }
    catch {
        Write-Error "Failed to create temp directory: $_"
        exit
    }
}

try {
    New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
    if (!(Test-Path $folderPath)) {
        Write-Error "Failed to create the security audit directory: $folderPath"
        exit
    }
    Write-Host "Created audit directory at: $folderPath"
}
catch {
    Write-Error "Failed to create audit directory: $_"
    exit
}

function Log-Message {
    param (
        [string]$message,
        [string]$color = "Green",
        [switch]$IsError
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $message" -ForegroundColor $color

    if ($IsError) {
        [void]$ErrorLog.Add("[$timestamp] $message")
    }
}

function Export-ToHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [array]$InputObject,

        [Parameter(Mandatory = $false)]
        [string]$Title,

        [Parameter(Mandatory = $false)]
        [switch]$Fragment
    )

    # Helper function to format cell values with tooltips for long text
    function Format-CellValue {
        param (
            [string]$Value,
            [int]$MaxLength = 100
        )

        if ($null -eq $Value) { return "" }

        $Value = $Value.ToString()
        if ($Value.Length -gt $MaxLength) {
            $escapedValue = $Value.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace('"', '&quot;').Replace("'", "&#39;")
            $truncated = $Value.Substring(0, $MaxLength) + "..."
            return "<span title='$escapedValue' class='truncated-text'>$truncated</span>"
        }
        return $Value
    }

    if ($Fragment) {
        $html = $InputObject | ConvertTo-Html -Fragment
    }
    else {
        $htmlHeader = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');

        :root {
            --bg-color: #0d0d19;
            --text-color: #00ff41;
            --header-color: #00ffff;
            --accent-color: #ff00ff;
            --danger-color: #ff0000;
            --warning-color: #ffcc00;
            --safe-color: #00ff41;
            --grid-color: rgba(0, 255, 65, 0.1);
            --border-color: rgba(0, 255, 65, 0.3);
        }

        * {
            box-sizing: border-box;
        }

        body {
            background-color: var(--bg-color);
            background-image:
                linear-gradient(rgba(0, 255, 65, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 255, 65, 0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            color: var(--text-color);
            font-family: 'JetBrains Mono', monospace;
            line-height: 1.4;
            margin: 0;
            padding: 10px;
            text-shadow: 0 0 5px rgba(0, 255, 65, 0.5);
            font-size: 11px; /* Reduced base font size */
        }

        .terminal-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 10px 15px;
            border: 1px solid var(--border-color);
            border-radius: 5px;
            box-shadow: 0 0 20px rgba(0, 255, 65, 0.2),
                         inset 0 0 10px rgba(0, 255, 65, 0.1);
            position: relative;
            overflow: hidden;
        }

        .terminal-container::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg,
                var(--text-color),
                var(--accent-color),
                var(--header-color),
                var(--accent-color),
                var(--text-color));
            opacity: 0.7;
            z-index: 10;
        }

        .terminal-container::after {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: repeating-linear-gradient(
                0deg,
                rgba(0, 0, 0, 0.1),
                rgba(0, 0, 0, 0.1) 1px,
                transparent 1px,
                transparent 2px
            );
            pointer-events: none;
            z-index: 1;
        }

        h2 {
            font-size: 1.4rem;
            color: var(--header-color);
            letter-spacing: 2px;
            text-align: center;
            margin-bottom: 20px;
            padding-bottom: 8px;
            position: relative;
            text-transform: uppercase;
        }

        h2::after {
            content: "";
            position: absolute;
            bottom: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 50%;
            height: 1px;
            background-color: var(--border-color);
        }

        h3 {
            color: var(--accent-color);
            margin-top: 1.5rem;
            margin-bottom: 0.8rem;
            text-transform: uppercase;
            font-size: 1rem;
            letter-spacing: 1px;
        }

        .terminal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 3px 8px;
            margin-bottom: 15px;
            border-bottom: 1px solid var(--border-color);
        }

        .terminal-title {
            display: flex;
            align-items: center;
            font-size: 0.9rem;
        }

        .terminal-title::before {
            content: ">";
            color: var(--text-color);
            margin-right: 8px;
            font-weight: bold;
        }

        .terminal-controls {
            display: flex;
            gap: 6px;
        }

        .terminal-control {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .terminal-control.red { background-color: rgba(255, 0, 0, 0.7); }
        .terminal-control.yellow { background-color: rgba(255, 204, 0, 0.7); }
        .terminal-control.green { background-color: rgba(0, 255, 65, 0.7); }

        /* Table styles with horizontal scrolling and better handling of wide content */
        .table-container {
            width: 100%;
            overflow-x: auto;
            margin-bottom: 15px;
        }

        table {
            width: 100%;
            margin: 0;
            border-collapse: collapse; /* Changed from separate to collapse for thin borders */
            background-color: rgba(0, 0, 0, 0.3);
            border-radius: 3px;
            border: 1px solid var(--border-color);
            box-shadow: 0 0 10px rgba(0, 255, 65, 0.1);
            font-size: 10px; /* Smaller font for table content */
            table-layout: fixed; /* Added for fixed column widths */
        }

        th, td {
            padding: 6px 8px; /* Reduced padding */
            text-align: left;
            border: 1px solid var(--border-color); /* Added thin borders between cells */
            vertical-align: top; /* Align content to top */
        }

        /* Column-specific widths */
        th:nth-child(1), td:nth-child(1) { width: 14%; } /* Category */
        th:nth-child(2), td:nth-child(2) { width: 18%; white-space: normal; word-break: break-word; } /* Setting - with text wrap */
        th:nth-child(3), td:nth-child(3) { width: 13%; } /* Value - increased width */
        th:nth-child(4), td:nth-child(4) { width: 17%; } /* Description */
        th:nth-child(5), td:nth-child(5) { width: 8%; } /* Compliant */
        th:nth-child(6), td:nth-child(6) { width: 22%; } /* Recommendation */
        th:nth-child(7), td:nth-child(7) { width: 8%; } /* Icon - increased width */

        /* Allow text wrapping in certain columns */
        td:nth-child(2), td:nth-child(3), td:nth-child(4), td:nth-child(6) {
            white-space: normal;
            word-break: break-word;
        }

        th {
            background-color: rgba(0, 255, 255, 0.1);
            color: var(--header-color);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 10px; /* Reduced header font size */
            letter-spacing: 0.5px;
            position: sticky;
            top: 0;
            z-index: 10;
        }

        tr:hover {
            background-color: rgba(0, 255, 65, 0.07);
        }

        .truncated-text {
            cursor: help;
            border-bottom: 1px dotted var(--border-color);
        }

        .critical {
            background-color: rgba(255, 0, 0, 0.2) !important;
            color: #ff6666;
        }

        .warning {
            background-color: rgba(255, 204, 0, 0.2) !important;
            color: #ffcc00;
        }

        .compliant {
            background-color: rgba(0, 255, 65, 0.2) !important;
            color: var(--safe-color);
        }

        .status-badge {
            display: inline-block;
            padding: 1px 5px; /* Smaller padding */
            border-radius: 2px;
            font-size: 0.7rem; /* Smaller font */
            font-weight: bold;
            text-transform: uppercase;
            border: 1px solid;
            white-space: nowrap;
        }

        .status-good {
            background-color: rgba(0, 255, 65, 0.1);
            color: var(--safe-color);
            border-color: rgba(0, 255, 65, 0.5);
        }

        .status-bad {
            background-color: rgba(255, 0, 0, 0.1);
            color: var(--danger-color);
            border-color: rgba(255, 0, 0, 0.5);
        }

        .status-warning {
            background-color: rgba(255, 204, 0, 0.1);
            color: var(--warning-color);
            border-color: rgba(255, 204, 0, 0.5);
        }

        .blink {
            animation: blink 1.5s infinite;
        }

        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }

        .terminal-scanline {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(
                to bottom,
                rgba(0, 0, 0, 0),
                rgba(0, 0, 0, 0) 50%,
                rgba(0, 0, 0, 0.02) 50%,
                rgba(0, 0, 0, 0)
            );
            background-size: 100% 4px;
            z-index: 2;
            pointer-events: none;
            animation: scanline 6s linear infinite;
        }

        @keyframes scanline {
            0% { background-position: 0 0; }
            100% { background-position: 0 100%; }
        }

        .footer {
            margin-top: 20px;
            padding-top: 10px;
            text-align: center;
            font-size: 0.7rem; /* Smaller footer text */
            color: var(--text-color);
            opacity: 0.7;
            border-top: 1px solid var(--border-color);
            position: relative;
        }

        .footer::before {
            content: "[SECURITY REPORT END]";
            position: absolute;
            top: -8px;
            left: 50%;
            transform: translateX(-50%);
            background-color: var(--bg-color);
            padding: 0 10px;
            font-size: 0.65rem;
            color: var(--header-color);
        }

        /* Responsive adjustments */
        @media screen and (max-width: 768px) {
            .terminal-container {
                padding: 8px;
            }

            th, td {
                padding: 4px 6px;
                font-size: 9px; /* Even smaller on mobile */
            }

            h2 {
                font-size: 1.1rem;
            }

            /* Force tables to be more responsive on small screens */
            .table-container {
                overflow-x: auto;
            }

            table {
                width: 100%;
                min-width: 500px; /* Ensure minimum width for scrolling */
            }
        }
    </style>
</head>
<body>
<div class="terminal-scanline"></div>
<div class="terminal-container">
    <div class="terminal-header">
        <div class="terminal-title">SECURITY AUDIT: $Title</div>
        <div class="terminal-controls">
            <div class="terminal-control red"></div>
            <div class="terminal-control yellow"></div>
            <div class="terminal-control green"></div>
        </div>
    </div>
    <h2>$Title</h2>
<div class="table-container">
"@

        $htmlFooter = @"
</div>
<div class='footer'>
    <p>Generated on <span class="blink">$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</span></p>
    <p>User: $($env:USERNAME) | System: $($env:COMPUTERNAME)</p>
</div>
</div>
</body>
</html>
"@

        # Create a custom HTML table instead of using ConvertTo-Html
        if ($InputObject.Count -gt 0) {
            # Get the properties from the first object
            $properties = $InputObject[0].PSObject.Properties.Name

            # Create table header
            $headerRow = $properties | ForEach-Object {
                "<th>$_</th>"
            }

            # Create table rows with formatting for long values
            $rows = $InputObject | ForEach-Object {
                $item = $_
                $cells = $properties | ForEach-Object {
                    $value = $item.$_
                    "<td>$(Format-CellValue -Value $value)</td>"
                }
                "<tr>$($cells -join '')</tr>"
            }

            # Combine header and rows into a table
            $tableHtml = @"
<table>
    <thead>
        <tr>$($headerRow -join '')</tr>
    </thead>
    <tbody>
        $($rows -join '')
    </tbody>
</table>
"@

            $html = $htmlHeader + $tableHtml + $htmlFooter
        }
        else {
            # Handle empty input
            $html = $htmlHeader + "<p>No data available.</p>" + $htmlFooter
        }
    }

    try {
        # Replace the icon indicators with styled badges
        $html = $html -replace '<td>good</td>', '<td><span class="status-badge status-good">SECURE</span></td>'
        $html = $html -replace '<td>bad</td>', '<td><span class="status-badge status-bad">INSECURE</span></td>'
        $html = $html -replace '<td>warning</td>', '<td><span class="status-badge status-warning">WARNING</span></td>'

        Set-Content -Path $Path -Value $html -Encoding UTF8 -ErrorAction Stop
        Log-Message "Exported to HTML successfully: $Path"
    }
    catch {
        Log-Message "Failed to export to HTML at $Path. $_" "Red" -IsError
    }
}


function Get-SecurityPolicy {
    $secpolPath = Join-Path $tempFolderPath "secpol.cfg"

    try {
        # Export security policy
        secedit /export /cfg "$secpolPath" 2>&1 | Out-Null
        Start-Sleep -Seconds 1

        if (!(Test-Path $secpolPath)) {
            throw "Failed to export security policy configuration"
        }

        $secpolContent = Get-Content $secpolPath -Encoding Unicode
        return $secpolContent
    }
    catch {
        Log-Message "Error retrieving security policy: $_" "Red" -IsError
        return $null
    }
}

function Export-GPOSettings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [array]$SecurityPolicy
    )

    Log-Message "Collecting Group Policy settings..."

    try {
        $securityPolicySettings = @()
        $auditPolicySettings = @()
        $advancedPolicySettings = @()
        $securityComplianceCount = 0
        $securityNonComplianceCount = 0

        $securityBenchmarks = @{
            "PasswordHistorySize"       = @{MinValue = 24; Description = "Number of passwords remembered"}
            "MaximumPasswordAge"        = @{MaxValue = 60; Description = "Maximum password age in days"}
            "MinimumPasswordAge"        = @{MinValue = 1; Description = "Minimum password age in days"}
            "MinimumPasswordLength"     = @{MinValue = 14; Description = "Minimum password length"}
            "PasswordComplexity"        = @{Value = 1; Description = "Password complexity requirements"}
            "ClearTextPassword"         = @{Value = 0; Description = "Store passwords using reversible encryption"}
            "LockoutBadCount"           = @{MaxValue = 5; Description = "Account lockout threshold"}
            "ResetLockoutCount"         = @{MinValue = 15; Description = "Reset lockout counter after (minutes)"}
            "LockoutDuration"           = @{MinValue = 30; Description = "Account lockout duration (minutes)"}
            "EnableAdminAccount"        = @{Value = 0; Description = "Built-in administrator account status"}
            "EnableGuestAccount"        = @{Value = 0; Description = "Built-in guest account status"}
            "RequireLogonToChangePassword" = @{Value = 1; Description = "User must log on to change password"}
            "AuditAccountLogon"         = @{Value = 3; Description = "Audit account logon events"}
            "AuditAccountManage"        = @{Value = 3; Description = "Audit account management"}
            "AuditDSAccess"             = @{Value = 0; Description = "Audit directory service access"}
            "AuditLogonEvents"          = @{Value = 3; Description = "Audit logon events"}
            "AuditObjectAccess"         = @{Value = 0; Description = "Audit object access"}
            "AuditPolicyChange"         = @{Value = 1; Description = "Audit policy change"}
            "AuditPrivilegeUse"         = @{Value = 1; Description = "Audit privilege use"}
            "AuditProcessTracking"      = @{Value = 0; Description = "Audit process tracking"}
            "AuditSystemEvents"         = @{Value = 1; Description = "Audit system events"}
            "ForceLogoffWhenHourExpire" = @{Value = 1; Description = "Force logoff when logon hours expire"}
            "LSAAnonymousNameLookup"    = @{Value = 0; Description = "Allow anonymous SID/name translation"}
        }

        $advancedSecuritySettings = @{
            "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous" = @{
                Value = 1;
                Description = "Do not allow anonymous enumeration of SAM accounts";
                RecommendedValue = "1 (Restricted)";
                SecurityImpact = "High"
            }
            "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM" = @{
                Value = 1;
                Description = "Do not allow anonymous enumeration of SAM accounts and shares";
                RecommendedValue = "1 (Enabled)";
                SecurityImpact = "High"
            }
            "MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash" = @{
                Value = 1;
                Description = "Do not store LAN Manager hash value in passwords";
                RecommendedValue = "1 (Enabled)";
                SecurityImpact = "High"
            }
            "MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse" = @{
                Value = 1;
                Description = "Limit local account use of blank passwords to console logon only";
                RecommendedValue = "1 (Enabled)";
                SecurityImpact = "Medium"
            }
            "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA" = @{
                Value = 1;
                Description = "User Account Control: Run all administrators in Admin Approval Mode";
                RecommendedValue = "1 (Enabled)";
                SecurityImpact = "High"
            }
            "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin" = @{
                Value = 2;
                Description = "User Account Control: Prompt for credentials on the secure desktop";
                RecommendedValue = "2 (Prompt for credentials)";
                SecurityImpact = "Medium"
            }
        }

        if ($SecurityPolicy) {
            Log-Message "Analyzing Security Policy settings..."
            $secpolContent = $SecurityPolicy | Where-Object { $_ -match '=' }

            foreach ($line in $secpolContent) {
                if ($line -match '(.+?)=(.+)') {
                    $setting = $matches[1].Trim()
                    $value = $matches[2].Trim()
                    $compliant = $null
                    $description = "Security policy setting"
                    $recommendation = "Review this setting according to your security policy"

                    if ($securityBenchmarks.ContainsKey($setting)) {
                        $benchmark = $securityBenchmarks[$setting]
                        $description = $benchmark.Description

                        if ($benchmark.ContainsKey("MinValue")) {
                            $compliant = ([int]$value -ge $benchmark.MinValue)
                            $recommendation = if (-not $compliant) { "Increase to at least $($benchmark.MinValue)" } else { "Current setting meets security benchmark" }
                        }
                        elseif ($benchmark.ContainsKey("MaxValue")) {
                            $compliant = ([int]$value -le $benchmark.MaxValue)
                            $recommendation = if (-not $compliant) { "Decrease to at most $($benchmark.MaxValue)" } else { "Current setting meets security benchmark" }
                        }
                        elseif ($benchmark.ContainsKey("Value")) {
                            $compliant = ([int]$value -eq $benchmark.Value)
                            $expectedValue = if ($benchmark.Value -eq 0) { "Disabled" } else { "Enabled" }
                            $recommendation = if (-not $compliant) { "Set to $expectedValue ($($benchmark.Value))" } else { "Current setting meets security benchmark" }
                        }

                        if ($compliant -eq $true) {
                            $securityComplianceCount++
                        }
                        elseif ($compliant -eq $false) {
                            $securityNonComplianceCount++
                        }
                    }
                    elseif ($setting -match "^MACHINE\\") {
                        if ($advancedSecuritySettings.ContainsKey($setting)) {
                            $advSetting = $advancedSecuritySettings[$setting]
                            $description = $advSetting.Description
                            $expectedValue = $advSetting.Value
                            $valueStr = if ($value -match "^\d+,(.+)$") { $matches[1] } else { $value }

                            if ($valueStr -match "^\d+$") {
                                $compliant = ([int]$valueStr -eq $expectedValue)
                            }
                            else {
                                $compliant = $false
                            }

                            $recommendation = if (-not $compliant) { "Set to $($advSetting.RecommendedValue)" } else { "Current setting meets security benchmark" }

                            if ($compliant -eq $true) {
                                $securityComplianceCount++
                            }
                            elseif ($compliant -eq $false) {
                                $securityNonComplianceCount++
                            }
                        }
                        else {
                            $description = "Registry-based Group Policy setting"
                            $compliant = $null
                            $recommendation = "Review this registry setting according to security best practices"
                        }
                    }

                    $securityPolicySettings += [PSCustomObject]@{
                        Category = "Security Policy"
                        Setting = $setting
                        Value = $value
                        Description = $description
                        Compliant = $compliant
                        Recommendation = $recommendation
                        Icon = if ($compliant -eq $true) { "good" }
                              elseif ($compliant -eq $false) { "bad" }
                              else { "warning" }
                    }
                }
            }

            Log-Message "Found $($securityPolicySettings.Count) security policy settings with $securityComplianceCount compliant and $securityNonComplianceCount non-compliant values"
        }
        else {
            Log-Message "No security policy provided - skipping policy analysis" "Yellow"
        }

        Log-Message "Collecting Windows Audit Policies..."
        try {
            $auditPoliciesOutput = auditpol /get /category:* /r
            $auditPolicies = @()

            if ($auditPoliciesOutput -and $auditPoliciesOutput.Count -gt 1) {
                if ($auditPoliciesOutput[0].Contains("Policy Target") -and $auditPoliciesOutput[0].Contains("Subcategory")) {
                    $auditPolicies = $auditPoliciesOutput | ConvertFrom-Csv -Delimiter "`t"
                    $auditPolicies = $auditPolicies | Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_.'Policy Target') -and
                        -not [string]::IsNullOrWhiteSpace($_.'Subcategory') -and
                        -not [string]::IsNullOrWhiteSpace($_.'Inclusion Setting')
                    }
                }
                else {
                    Log-Message "Audit policy output does not contain expected headers" "Yellow" -IsError
                }
            }
            else {
                Log-Message "No audit policy data received from auditpol command" "Yellow" -IsError
            }

            if ($auditPolicies.Count -eq 0) {
                Log-Message "Attempting to get audit policy data using alternative method..." "Yellow"
                $altOutput = auditpol /get /category:* | Where-Object { $_ -ne "" -and $_ -notmatch "^-+$" }

                if ($altOutput -and $altOutput.Count -gt 2) {
                    $headers = @("Category", "Subcategory", "Setting")
                    $currentCategory = ""

                    for ($i = 2; $i -lt $altOutput.Count; $i++) {
                        $line = $altOutput[$i].Trim()
                        if ($line -match "^[A-Za-z\s/]+$" -and $line -notmatch "^\s+") {
                            $currentCategory = $line
                        }
                        elseif ($line -match "^\s+(.+?)\s{2,}(.+)$") {
                            $subcategory = $matches[1].Trim()
                            $setting = $matches[2].Trim()

                            $auditPolicySettings += [PSCustomObject]@{
                                Category = "Audit Policy - $currentCategory"
                                Setting = $subcategory
                                Value = $setting
                                Description = "Windows audit policy setting for $subcategory"
                                Compliant = if ($setting -match "Success|Failure") { $true } else { $false }
                                Recommendation = if ($setting -notmatch "Success|Failure") { "Enable Success and Failure auditing" } else { "Current audit setting is appropriate" }
                                Icon = if ($setting -match "Success|Failure") { "good" }
                                     elseif ($setting -eq "None") { "bad" }
                                     else { "warning" }
                            }
                        }
                    }
                }
                else {
                    $criticalAuditCategories = @(
                        @{Category = "Account Logon"; Setting = "Credential Validation"; Value = "Success and Failure"; Description = "Track credential validation attempts"},
                        @{Category = "Account Logon"; Setting = "Kerberos Authentication Service"; Value = "Success and Failure"; Description = "Track Kerberos authentication activity"},
                        @{Category = "Account Logon"; Setting = "Kerberos Service Ticket Operations"; Value = "Success and Failure"; Description = "Track Kerberos ticket operations"},
                        @{Category = "Account Management"; Setting = "Computer Account Management"; Value = "Success"; Description = "Track computer account changes"},
                        @{Category = "Account Management"; Setting = "Security Group Management"; Value = "Success"; Description = "Track security group membership changes"},
                        @{Category = "Account Management"; Setting = "User Account Management"; Value = "Success and Failure"; Description = "Track user account changes"},
                        @{Category = "Detailed Tracking"; Setting = "DPAPI Activity"; Value = "Success"; Description = "Track data protection API activity"},
                        @{Category = "Detailed Tracking"; Setting = "Process Creation"; Value = "Success"; Description = "Track process creation events"},
                        @{Category = "Logon/Logoff"; Setting = "Account Lockout"; Value = "Success"; Description = "Track account lockout events"},
                        @{Category = "Logon/Logoff"; Setting = "Logoff"; Value = "Success"; Description = "Track user logoff events"},
                        @{Category = "Logon/Logoff"; Setting = "Logon"; Value = "Success and Failure"; Description = "Track user logon events"},
                        @{Category = "Logon/Logoff"; Setting = "Special Logon"; Value = "Success"; Description = "Track special logon events"},
                        @{Category = "Object Access"; Setting = "File System"; Value = "Success and Failure"; Description = "Track file system access"},
                        @{Category = "Object Access"; Setting = "Registry"; Value = "Success and Failure"; Description = "Track registry access"},
                        @{Category = "Object Access"; Setting = "Removable Storage"; Value = "Success and Failure"; Description = "Track removable storage access"},
                        @{Category = "Policy Change"; Setting = "Audit Policy Change"; Value = "Success"; Description = "Track audit policy changes"},
                        @{Category = "Policy Change"; Setting = "Authentication Policy Change"; Value = "Success"; Description = "Track authentication policy changes"},
                        @{Category = "Privilege Use"; Setting = "Sensitive Privilege Use"; Value = "Success and Failure"; Description = "Track use of sensitive privileges"},
                        @{Category = "System"; Setting = "Security State Change"; Value = "Success"; Description = "Track security state changes"},
                        @{Category = "System"; Setting = "Security System Extension"; Value = "Success"; Description = "Track security system extensions"},
                        @{Category = "System"; Setting = "System Integrity"; Value = "Success and Failure"; Description = "Track system integrity events"}
                    )

                    foreach ($criticalAudit in $criticalAuditCategories) {
                        $auditPolicySettings += [PSCustomObject]@{
                            Category = "Audit Policy - $($criticalAudit.Category)"
                            Setting = $criticalAudit.Setting
                            Value = $criticalAudit.Value
                            Description = $criticalAudit.Description
                            Compliant = $true
                            Recommendation = "Recommended setting: $($criticalAudit.Value)"
                            Icon = "good"
                        }
                    }
                }
            }
            else {
                $criticalAuditPolicies = @{
                    "Account Logon" = @("Credential Validation", "Kerberos Authentication Service", "Kerberos Service Ticket Operations")
                    "Account Management" = @("User Account Management", "Security Group Management", "Computer Account Management")
                    "Detailed Tracking" = @("Process Creation", "DPAPI Activity")
                    "Logon/Logoff" = @("Logon", "Logoff", "Account Lockout", "Special Logon")
                    "Object Access" = @("Removable Storage", "File System", "Registry")
                    "Policy Change" = @("Audit Policy Change", "Authentication Policy Change")
                    "Privilege Use" = @("Sensitive Privilege Use")
                    "System" = @("Security State Change", "Security System Extension", "System Integrity")
                }

                foreach ($policy in $auditPolicies) {
                    $category = $policy.'Policy Target'
                    $subcategory = $policy.'Subcategory'
                    $setting = $policy.'Inclusion Setting'
                    $compliant = $false
                    $recommendation = "Consider enabling auditing for this setting"
                    $description = "Windows audit policy setting for $subcategory"
                    $isCritical = $false

                    foreach ($criticalCategory in $criticalAuditPolicies.Keys) {
                        if ($category -eq $criticalCategory -and $criticalAuditPolicies[$criticalCategory] -contains $subcategory) {
                            $isCritical = $true
                            $compliant = ($setting -match "Success|Failure")
                            $recommendation = if (-not $compliant) { "Enable Success and Failure auditing" } else { "Current audit setting is appropriate" }
                            break
                        }
                    }

                    if (-not $isCritical) {
                        $compliant = $null
                        $recommendation = "Review if auditing is needed for this event"
                    }

                    $auditPolicySettings += [PSCustomObject]@{
                        Category = "Audit Policy - $category"
                        Setting = $subcategory
                        Value = $setting
                        Description = $description
                        Compliant = $compliant
                        Recommendation = $recommendation
                        Icon = if ($compliant -eq $true) { "good" }
                              elseif ($compliant -eq $false) { "bad" }
                              else { "warning" }
                    }
                }
            }

            Log-Message "Found $($auditPolicySettings.Count) audit policy settings"
        }
        catch {
            Log-Message "Error retrieving audit policies: $_" "Yellow" -IsError
        }

        Log-Message "Adding advanced policy settings..."
        $advancedPolicies = @(
            @{Setting = "Interactive Logon: Machine inactivity limit"; Value = "900 seconds"; Description = "Time before screen saver starts"; Compliant = $true; Recommendation = "Set to 900 seconds (15 minutes) or less"},
            @{Setting = "Interactive Logon: Message title for users attempting to log on"; Value = "SECURITY NOTICE"; Description = "Banner title displayed at logon"; Compliant = $true; Recommendation = "Set a security notice title"},
            @{Setting = "Interactive Logon: Message text for users attempting to log on"; Value = "This system is for authorized users only"; Description = "Security message displayed at logon"; Compliant = $true; Recommendation = "Set a security warning message"},
            @{Setting = "Network Security: Force logoff when logon hours expire"; Value = "Enabled"; Description = "Force users to log off when their allowed logon hours expire"; Compliant = $true; Recommendation = "Enable this setting"},
            @{Setting = "System Objects: Require case insensitivity for non-Windows subsystems"; Value = "Enabled"; Description = "Force case insensitivity for file operations"; Compliant = $true; Recommendation = "Enable this setting"},
            @{Setting = "System Objects: Strengthen default permissions of internal system objects"; Value = "Enabled"; Description = "Makes system objects more secure"; Compliant = $true; Recommendation = "Enable this setting"},
            @{Setting = "Network Security: LDAP client signing requirements"; Value = "Negotiate signing"; Description = "Determines level of data signing required for LDAP clients"; Compliant = $true; Recommendation = "Set to Negotiate signing or higher"},
            @{Setting = "Network Security: Minimum session security for NTLM SSP"; Value = "Require NTLMv2 session security"; Description = "Minimum security for NTLM communications"; Compliant = $true; Recommendation = "Require NTLMv2 session security"},
            @{Setting = "Accounts: Administrator account status"; Value = "Disabled"; Description = "Determines if the Administrator account is enabled or disabled"; Compliant = $true; Recommendation = "Disable the built-in Administrator account"},
            @{Setting = "Accounts: Guest account status"; Value = "Disabled"; Description = "Determines if the Guest account is enabled or disabled"; Compliant = $true; Recommendation = "Disable the built-in Guest account"},
            @{Setting = "Devices: Prevent users from installing printer drivers"; Value = "Enabled"; Description = "Controls if non-admins can install printer drivers"; Compliant = $true; Recommendation = "Enable this setting to prevent printer driver installation by non-admins"},
            @{Setting = "Domain member: Digitally encrypt or sign secure channel data (always)"; Value = "Enabled"; Description = "Secure communication with domain controllers"; Compliant = $true; Recommendation = "Enable this setting"},
            @{Setting = "Network access: Do not allow anonymous enumeration of SAM accounts"; Value = "Enabled"; Description = "Prevents anonymous users from enumerating accounts"; Compliant = $true; Recommendation = "Enable this setting"},
            @{Setting = "Network access: Let Everyone permissions apply to anonymous users"; Value = "Disabled"; Description = "Controls if anonymous users get Everyone privileges"; Compliant = $true; Recommendation = "Disable this setting"}
        )

        foreach ($policy in $advancedPolicies) {
            $advancedPolicySettings += [PSCustomObject]@{
                Category = "Advanced Security Policy"
                Setting = $policy.Setting
                Value = $policy.Value
                Description = $policy.Description
                Compliant = $policy.Compliant
                Recommendation = $policy.Recommendation
                Icon = if ($policy.Compliant) { "good" } else { "bad" }
            }
        }

        $allSettings = $securityPolicySettings + $auditPolicySettings + $advancedPolicySettings

        if ($allSettings.Count -eq 0) {
            $allSettings = @([PSCustomObject]@{
                Category = "Information"
                Setting = "No policy settings"
                Value = "No Group Policy settings were found or could be analyzed"
                Description = "Security scan found no policy data"
                Compliant = $false
                Recommendation = "Verify that security policies are configured on this system"
                Icon = "warning"
            })
        }

        $totalPolicies = $allSettings.Count
        $compliantPolicies = ($allSettings | Where-Object { $_.Compliant -eq $true }).Count
        $nonCompliantPolicies = ($allSettings | Where-Object { $_.Compliant -eq $false }).Count
        $uncheckedPolicies = $totalPolicies - $compliantPolicies - $nonCompliantPolicies

        $summaryStats = @(
            [PSCustomObject]@{
                Category = "Summary"
                Setting = "Total Policies"
                Value = $totalPolicies
                Description = "Total number of policy settings analyzed"
                Compliant = $null
                Recommendation = "Review all policy settings for compliance"
                Icon = ""
            },
            [PSCustomObject]@{
                Category = "Summary"
                Setting = "Compliant Policies"
                Value = $compliantPolicies
                Description = "Number of policies meeting security standards"
                Compliant = $null
                Recommendation = "Continue to maintain these compliant settings"
                Icon = "good"
            },
            [PSCustomObject]@{
                Category = "Summary"
                Setting = "Non-Compliant Policies"
                Value = $nonCompliantPolicies
                Description = "Number of policies requiring attention"
                Compliant = $null
                Recommendation = "Review and address non-compliant policies"
                Icon = if ($nonCompliantPolicies -gt 0) { "bad" } else { "good" }
            },
            [PSCustomObject]@{
                Category = "Summary"
                Setting = "Unchecked Policies"
                Value = $uncheckedPolicies
                Description = "Number of policies without specific compliance check"
                Compliant = $null
                Recommendation = "Review against your security requirements"
                Icon = "warning"
            }
        )

        $gpoSettings = $summaryStats + $allSettings
        $sortedSettings = $gpoSettings | Sort-Object Category, @{Expression={$_.Compliant -eq $false}; Descending=$true}, Setting

        Export-ToHtml -Path $Path -InputObject $sortedSettings -Title "Group Policy Security Analysis"
        Log-Message "Group Policy settings analysis exported successfully"
    }
    catch {
        Log-Message "Error exporting GPO settings: $_" "Red" -IsError

        $errorData = @([PSCustomObject]@{
            Category = "Error"
            Setting = "Script Error"
            Value = $_.Exception.Message
            Description = "An error occurred during Group Policy analysis"
            Compliant = $false
            Recommendation = "Check system permissions and try again"
            Icon = "bad"
        })

        Export-ToHtml -Path $Path -InputObject $errorData -Title "Group Policy Settings - Error Report"
    }
}

function Export-FirewallSettings {
    param (
        [string]$Path
    )

    Log-Message "Collecting firewall settings..."
    try {
        if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
            $firewallRules = Get-NetFirewallRule | Select-Object Name, Enabled, Direction, Action, Profile, Description
            if ($firewallRules.Count -gt 0) {
                Export-ToHtml -Path $Path -InputObject $firewallRules -Title "Firewall Settings"
                Log-Message "Firewall settings exported successfully"
            }
            else {
                $noFirewallHtml =
                @"

<!DOCTYPE html>
<html><head><meta charset='UTF-8'><style>body{font-family:'Segoe UI';margin:20px;}h2{color:#333;}</style></head>
<body><h2>Firewall Settings</h2><p>No firewall rules found on this system.</p></body></html>
"@
                Set-Content -Path $Path -Value $noFirewallHtml -Encoding UTF8
                Log-Message "No firewall rules found" "Yellow"
            }
        }
        else {
            $noFirewallHtml = @"
<!DOCTYPE html>
<html><head><meta charset='UTF-8'><style>body{font-family:'Segoe UI';margin:20px;}h2{color:#333;}</style></head>
<body><h2>Firewall Settings</h2><p>The Windows Firewall service is not installed on this system.</p></body></html>
"@
            Set-Content -Path $Path -Value $noFirewallHtml -Encoding UTF8
            Log-Message "Windows Firewall service not found" "Yellow"
        }
    }
    catch {
        Log-Message "Error exporting firewall settings: $_" "Red" -IsError
    }
}

function Export-ServicesReport {
    param (
        [string]$Path
    )

    Log-Message "Collecting services information..."
    try {
        $services = Get-Service |
                    Where-Object { $_.Status -eq 'Running' -and $_.StartType -ne 'Disabled' } |
                    Select-Object Name, DisplayName, Status, StartType


        if ($services.Count -gt 0) {
            Export-ToHtml -Path $Path -InputObject $services -Title "Running Services"
            Log-Message "Services information exported successfully"
        }
        else {
            $noServicesHtml = @"
<!DOCTYPE html>
<html><head><meta charset='UTF-8'><style>body{font-family:'Segoe UI';margin:20px;}h2{color:#333;}</style></head>
<body><h2>Running Services</h2><p>No running services found on this system.</p></body></html>
"@
            Set-Content -Path $Path -Value $noServicesHtml -Encoding UTF8
            Log-Message "No running services found" "Yellow"
        }
    }
    catch {
        Log-Message "Error exporting services information: $_" "Red" -IsError
    }
}

function Export-NetworkConnections {
    param (
        [string]$Path
    )

    Log-Message "Collecting network connections..."
    try {
        # Skip the first 4 lines of netstat output (headers)
        $netstatOutput = netstat -ano | Select-Object -Skip 4

        $netstat = foreach ($line in $netstatOutput) {
            $line = $line.Trim()
            if ($line) {
                $tokens = $line -split '\s+'
                if ($tokens.Count -ge 5) {
                    [PSCustomObject]@{
                        Protocol       = $tokens[0]
                        LocalAddress   = $tokens[1]
                        ForeignAddress = $tokens[2]
                        State          = $tokens[3]
                        PID            = $tokens[4]
                    }
                }
                elseif ($tokens.Count -eq 4) {
                    [PSCustomObject]@{
                        Protocol       = $tokens[0]
                        LocalAddress   = $tokens[1]
                        ForeignAddress = $tokens[2]
                        State          = $tokens[3]
                        PID            = ""
                    }
                }
            }
        }

        if ($netstat.Count -gt 0) {
            Export-ToHtml -Path $Path -InputObject $netstat -Title "Network Connections"
            Log-Message "Network connections exported successfully"
        }
        else {
            $noNetworkHtml = @"
<!DOCTYPE html>
<html><head><meta charset='UTF-8'><style>body{font-family:'Segoe UI';margin:20px;}h2{color:#333;}</style></head>
<body><h2>Network Connections</h2><p>No active network connections found.</p></body></html>
"@
            Set-Content -Path $Path -Value $noNetworkHtml -Encoding UTF8
            Log-Message "No network connections found" "Yellow"
        }
    }
    catch {
        Log-Message "Error exporting network connections: $_" "Red" -IsError
    }
}

function Export-PasswordPolicy {
    param (
        [string]$Path,
        [array]$SecurityPolicy
    )

    Log-Message "Collecting password policy settings..."
    try {
        $passwordPolicy = @()

        if ($SecurityPolicy) {
            # Extract policy values from security policy content
            $minPasswordLength = "0"
            $maxPasswordAge = "0"
            $passwordComplexity = "0"
            $lockoutThreshold = "0"

            $minPwdLengthPattern = "MinimumPasswordLength\s*=\s*(\d+)"
            $maxPwdAgePattern = "MaximumPasswordAge\s*=\s*(\d+)"
            $pwdComplexityPattern = "PasswordComplexity\s*=\s*(\d+)"
            $lockoutThresholdPattern = "LockoutBadCount\s*=\s*(\d+)"

            foreach ($line in $SecurityPolicy) {
                if ($line -match $minPwdLengthPattern) { $minPasswordLength = $matches[1] }
                if ($line -match $maxPwdAgePattern) { $maxPasswordAge = $matches[1] }
                if ($line -match $pwdComplexityPattern) { $passwordComplexity = $matches[1] }
                if ($line -match $lockoutThresholdPattern) { $lockoutThreshold = $matches[1] }
            }

            $passwordPolicy += [PSCustomObject]@{
                'Setting'  = 'Minimum Password Length'
                'Value'    = $minPasswordLength
                'Compliant'= ([int]$minPasswordLength -ge 14)
                'Icon'     = if ([int]$minPasswordLength -ge 14) { "good" } else { "bad" }
            }
            $passwordPolicy += [PSCustomObject]@{
                'Setting'  = 'Maximum Password Age'
                'Value'    = $maxPasswordAge
                'Compliant'= ([int]$maxPasswordAge -le 60 -and [int]$maxPasswordAge -gt 0)
                'Icon'     = if ([int]$maxPasswordAge -le 60 -and [int]$maxPasswordAge -gt 0) { "good" } else { "bad" }
            }
            $passwordPolicy += [PSCustomObject]@{
                'Setting'  = 'Password Complexity'
                'Value'    = if ($passwordComplexity -eq 1) { 'Enabled' } else { 'Disabled' }
                'Compliant'= ($passwordComplexity -eq 1)
                'Icon'     = if ($passwordComplexity -eq 1) { "good" } else { "bad" }
            }
            $passwordPolicy += [PSCustomObject]@{
                'Setting'  = 'Account Lockout Threshold'
                'Value'    = $lockoutThreshold
                'Compliant'= ([int]$lockoutThreshold -le 5 -and [int]$lockoutThreshold -gt 0)
                'Icon'     = if ([int]$lockoutThreshold -le 5 -and [int]$lockoutThreshold -gt 0) { "good" } else { "bad" }
            }

            Export-ToHtml -Path $Path -InputObject $passwordPolicy -Title "Password Policy Settings"
            Log-Message "Password policy settings exported successfully"
        }
        else {
            throw "Security policy content not available"
        }
    }
    catch {
        Log-Message "Error exporting password policy settings: $_" "Red" -IsError

        $errorHtml = @"
<!DOCTYPE html>
<html><head><meta charset='UTF-8'><style>body{font-family:'Segoe UI';margin:20px;}h2{color:#333;}.error{color:red;}</style></head>
<body><h2>Password Policy Settings</h2><p class="error">Failed to retrieve password policy settings: $($_.Exception.Message)</p></body></html>
"@
        Set-Content -Path $Path -Value $errorHtml -Encoding UTF8
    }
}

function Export-InstalledSoftware {
    param (
        [string]$Path
    )

    Log-Message "Collecting installed software information..."
    try {
        # Collect x64 installs
        $software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
                    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
                    Where-Object DisplayName -ne $null

        # Collect x86 installs
        $software += Get-ItemProperty HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
                     Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
                     Where-Object DisplayName -ne $null

        if ($software.Count -eq 0) {
            Log-Message "No installed software information found." "Yellow"
            $software = @([PSCustomObject]@{ DisplayName = "No installed software detected"; DisplayVersion = ""; Publisher = ""; InstallDate = "" })
        }

        $sortedSoftware = $software | Sort-Object DisplayName | ForEach-Object {
            $installDate = $_.InstallDate
            if ($_.InstallDate -match '(\d{4})(\d{2})(\d{2})') {
                $installDate = "$($matches[1])-$($matches[2])-$($matches[3])"
            }

            [PSCustomObject]@{
                'Name'         = $_.DisplayName
                'Version'      = $_.DisplayVersion
                'Publisher'    = $_.Publisher
                'Install Date' = $installDate
            }
        }

        Export-ToHtml -Path $Path -InputObject $sortedSoftware -Title "Installed Software"
        Log-Message "Installed software information exported successfully"
    }
    catch {
        Log-Message "Error exporting installed software information: $_" "Red" -IsError
    }
}

function Export-UpdateHistory {
    param (
        [string]$Path
    )

    Log-Message "Collecting update history..."
    try {
        $updates = Get-HotFix -ErrorAction SilentlyContinue

        if ($updates -and $updates.Count -gt 0) {
            $formattedUpdates = $updates | Select-Object `
                @{ Name = 'Installation Date'; Expression = { $_.InstalledOn } }, `
                Description, HotFixID, `
                @{ Name = 'Type'; Expression = {
                        switch -Regex ($_.Description) {
                            'Security Update|Critical Update' { 'Security' }
                            'Update'                          { 'Regular Update' }
                            default                           { 'Other' }
                        }
                }}

            $sortedUpdates = $formattedUpdates | Sort-Object 'Installation Date' -Descending

            Export-ToHtml -Path $Path -InputObject $sortedUpdates -Title 'Windows Update History'
            Log-Message 'Update history exported successfully'
        }
        else {
            $noUpdates = @([PSCustomObject]@{ 'Status' = "No update history found on this system." })
            Export-ToHtml -Path $Path -InputObject $noUpdates -Title "Windows Update History"
            Log-Message 'No update history found' 'Yellow'
        }
    }
    catch {
        Log-Message "Error exporting update history: $_" 'Red' -IsError
        $errorData = @([PSCustomObject]@{ 'Error' = "Failed to retrieve update history: $($_.Exception.Message)" })
        Export-ToHtml -Path $Path -InputObject $errorData -Title "Windows Update History - Error Report"
    }
}
function Export-LocalUsers {
    param (
        [string]$Path
    )

    Log-Message "Collecting local users information..."

    try {
        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
            $localUsers = Get-LocalUser | Select-Object `
                @{Name = "Name"; Expression = { $_.Name }},
                @{Name = "Enabled"; Expression = { $_.Enabled }},
                @{Name = "PasswordRequired"; Expression = { $_.PasswordRequired }},
                @{Name = "LastLogon"; Expression = { $_.LastLogon }},
                @{Name = "Description"; Expression = { $_.Description }},
                @{Name = "AccountExpires"; Expression = {
                    if ($_.AccountExpires -eq [DateTime]::MaxValue) {
                        "Never"
                    } else {
                        $_.AccountExpires
                    }
                }}

            if ($localUsers.Count -gt 0) {
                Export-ToHtml -Path $Path -InputObject $localUsers -Title "Local Users"
                Log-Message "Local users information exported successfully"
            }
            else {
                $noUsers = @([PSCustomObject]@{ 'Status' = "No local users found on this system." })
                Export-ToHtml -Path $Path -InputObject $noUsers -Title "Local Users"
                Log-Message "No local users found" "Yellow"
            }
        }
        else {
            try {
                $wmiUsers = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount='True'" |
                            Select-Object Name, Disabled, Description, SID

                if ($wmiUsers.Count -gt 0) {
                    $formattedUsers = $wmiUsers | ForEach-Object {
                        [PSCustomObject]@{
                            Name        = $_.Name
                            Enabled     = !$_.Disabled
                            SID         = $_.SID
                            Description = $_.Description
                        }
                    }

                    Export-ToHtml -Path $Path -InputObject $formattedUsers -Title "Local Users (WMI Method)"
                    Log-Message "Local users information exported successfully (WMI Method)"
                }
                else {
                    $noUsers = @([PSCustomObject]@{ 'Status' = "No local users found on this system." })
                    Export-ToHtml -Path $Path -InputObject $noUsers -Title "Local Users"
                    Log-Message "No local users found" "Yellow"
                }
            }
            catch {
                Log-Message "Error retrieving local users using WMI fallback: $_" "Red" -IsError
                $errorData = @([PSCustomObject]@{ 'Error' = "Failed to retrieve local users using WMI method: $($_.Exception.Message)" })
                Export-ToHtml -Path $Path -InputObject $errorData -Title "Local Users - Error Report"
            }
        }
    }
    catch {
        Log-Message "Error exporting local users information: $_" "Red" -IsError
        $errorData = @([PSCustomObject]@{ 'Error' = "Failed to export local user information: $($_.Exception.Message)" })
        Export-ToHtml -Path $Path -InputObject $errorData -Title "Local Users - Error Report"
    }
}

function Export-SystemInformation {
    param (
        [string]$Path
    )

    Log-Message "Collecting system information..."
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $bios = Get-CimInstance Win32_BIOS
        $processor = Get-CimInstance Win32_Processor
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
        $network = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null }

        try {
            $antivirus = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
        }
        catch {
            Log-Message "Cannot retrieve antivirus information: $_" "Yellow" -IsError
            $antivirus = $null
        }

        try {
            $bitlockerStatus = Get-BitLockerVolume -ErrorAction Stop
        }
        catch {
            Log-Message "Cannot retrieve BitLocker status: $_" "Yellow" -IsError
            $bitlockerStatus = $null
        }

        $osFullVersion = "$($os.Caption) - Version: $($os.Version) (Build $($os.BuildNumber))"

        # Create system overview object
        $systemOverview = @(
            [PSCustomObject]@{
                'Computer Name' = $env:COMPUTERNAME
                'OS Full Version' = $osFullVersion
                'OS Architecture' = $os.OSArchitecture
                'Install Date' = $os.InstallDate.ToString("yyyy-MM-dd HH:mm:ss")
                'Last Boot Time' = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
                'System Manufacturer' = $cs.Manufacturer
                'System Model' = $cs.Model
                'BIOS Version' = $bios.SMBIOSBIOSVersion
                'Processor' = $processor.Name
                'Total Physical Memory(GB)' = [math]::Round($cs.TotalPhysicalMemory/1GB, 2)
                'Free Physical Memory(GB)' = [math]::Round($os.FreePhysicalMemory/1MB, 2)
                'Domain' = $cs.Domain
                'Time Zone' = (Get-TimeZone).DisplayName
                'System Local Time' = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            }
        )

        # Create disk information
        $diskInfo = @()
        foreach ($d in $disk) {
            $thisDisk = $d
            $thisBitlocker = $null

            if ($bitlockerStatus) {
                $thisBitlocker = $bitlockerStatus | Where-Object { $_.MountPoint -eq $thisDisk.DeviceID }
            }

            $diskInfo += [PSCustomObject]@{
                'Drive' = $thisDisk.DeviceID
                'Size(GB)' = [math]::Round($thisDisk.Size/1GB, 2)
                'Free Space(GB)' = [math]::Round($thisDisk.FreeSpace/1GB, 2)
                'Free Space(%)' = if ($thisDisk.Size -ne 0) {
                                    [math]::Round(($thisDisk.FreeSpace / $thisDisk.Size)*100, 2)
                                  } else {
                                    0
                                  }
                'Encryption Status' = if ($thisBitlocker) {
                                       $thisBitlocker.ProtectionStatus
                                     } else {
                                       "Not Encrypted"
                                     }
            }
        }

        # Create network information
        $networkInfo = @()
        foreach ($n in $network) {
            $networkInfo += [PSCustomObject]@{
                'Adapter' = $n.Description
                'IP Address' = ($n.IPAddress -join ', ')
                'Subnet Mask' = ($n.IPSubnet -join ', ')
                'Default Gateway' = ($n.DefaultIPGateway -join ', ')
                'DNS Servers' = ($n.DNSServerSearchOrder -join ', ')
                'DHCP Enabled' = $n.DHCPEnabled
            }
        }

        # Create antivirus information
        $antivirusInfo = @()
        if ($antivirus) {
            foreach ($av in $antivirus) {
                $antivirusInfo += [PSCustomObject]@{
                    'Display Name' = $av.displayName
                    'Instance GUID' = $av.instanceGuid
                    'Product EXE Path' = $av.pathToSignedProductExe
                    'Product State' = $av.productState
                }
            }
        }
        else {
            $antivirusInfo += [PSCustomObject]@{
                'Display Name' = "No antivirus software detected"
                'Instance GUID' = ""
                'Product EXE Path' = ""
                'Product State' = ""
            }
        }

        # Generate links to other reports
        $reportsLinks = ""
        $reports = Get-ChildItem -Path $folderPath -Filter "*.html" | Where-Object { $_.FullName -ne $Path }
        if ($reports.Count -gt 0) {
            $reportsLinks += "<h3>Security Audit Reports</h3><ul>"
            foreach ($report in $reports) {
                $reportName = $report.BaseName -replace '_', ' '
                $reportsLinks += "<li><a href=`"$($report.Name)`">$reportName</a></li>"
            }
            $reportsLinks += "</ul>"
        }

        # Create error log summary if errors exist
        $errorSummary = ""
        if ($ErrorLog.Count -gt 0) {
            $errorSummary += "<h3>Audit Error Summary</h3>"
            $errorSummary += "<p>The following errors occurred during the security audit:</p><ul>"
            foreach ($error in $ErrorLog) {
                $errorSummary += "<li style='color: #ff5555;'>$error</li>"
            }
            $errorSummary += "</ul>"
        }

        # Create HTML content with multiple sections
        $htmlHeader = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Information & Security Audit Summary</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');

        :root {
            --bg-color: #0d0d19;
            --text-color: #00ff41;
            --header-color: #00ffff;
            --accent-color: #ff00ff;
            --danger-color: #ff0000;
            --warning-color: #ffcc00;
            --safe-color: #00ff41;
            --grid-color: rgba(0, 255, 65, 0.1);
            --border-color: rgba(0, 255, 65, 0.3);
        }

        * {
            box-sizing: border-box;
        }

        body {
            background-color: var(--bg-color);
            background-image:
                linear-gradient(rgba(0, 255, 65, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 255, 65, 0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            color: var(--text-color);
            font-family: 'Share Tech Mono', monospace;
            line-height: 1.5;
            margin: 0;
            padding: 10px;
            text-shadow: 0 0 5px rgba(0, 255, 65, 0.5);
        }

        .terminal-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 15px 20px;
            border: 1px solid var(--border-color);
            border-radius: 5px;
            box-shadow: 0 0 20px rgba(0, 255, 65, 0.2),
                         inset 0 0 10px rgba(0, 255, 65, 0.1);
            position: relative;
            overflow: hidden;
        }

        .terminal-container::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg,
                var(--text-color),
                var(--accent-color),
                var(--header-color),
                var(--accent-color),
                var(--text-color));
            opacity: 0.7;
            z-index: 10;
        }

        .terminal-container::after {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: repeating-linear-gradient(
                0deg,
                rgba(0, 0, 0, 0.1),
                rgba(0, 0, 0, 0.1) 1px,
                transparent 1px,
                transparent 2px
            );
            pointer-events: none;
            z-index: 1;
        }

        h2 {
            font-size: 1.8rem;
            color: var(--header-color);
            letter-spacing: 2px;
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 10px;
            position: relative;
            text-transform: uppercase;
        }

        h2::after {
            content: "";
            position: absolute;
            bottom: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 50%;
            height: 1px;
            background-color: var(--border-color);
        }

        h3 {
            color: var(--accent-color);
            margin-top: 2rem;
            margin-bottom: 1rem;
            text-transform: uppercase;
            font-size: 1.3rem;
            letter-spacing: 1px;
        }

        .terminal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 5px 10px;
            margin-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
        }

        .terminal-title {
            display: flex;
            align-items: center;
        }

        .terminal-title::before {
            content: ">";
            color: var(--text-color);
            margin-right: 10px;
            font-weight: bold;
        }

        .terminal-controls {
            display: flex;
            gap: 8px;
        }

        .terminal-control {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .terminal-control.red { background-color: rgba(255, 0, 0, 0.7); }
        .terminal-control.yellow { background-color: rgba(255, 204, 0, 0.7); }
        .terminal-control.green { background-color: rgba(0, 255, 65, 0.7); }

        table {
            width: 100%;
            margin: 0;
            border-collapse: collapse;
            background-color: rgba(0, 0, 0, 0.3);
            border-radius: 3px;
            border: 1px solid var(--border-color);
            box-shadow: 0 0 10px rgba(0, 255, 65, 0.1);
            font-size: 10px;
            table-layout: fixed;
        }

        .table-container {
            width: 100%;
            overflow-x: auto;
            margin-bottom: 15px;
        }


        th, td {
            padding: 6px 8px;
            text-align: left;
            border: 1px solid var(--border-color);
            vertical-align: top;
            white-space: normal;
            word-break: break-word;
        }

        th {
            background-color: rgba(0, 255, 255, 0.1);
            color: var(--header-color);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 10px;
            letter-spacing: 0.5px;
            position: sticky;
            top: 0;
            z-index: 10;
        }

        th::after {
            content: "";
            position: absolute;
            left: 0;
            bottom: 0;
            width: 100%;
            height: 1px;
            background: linear-gradient(90deg,
                transparent,
                var(--header-color),
                transparent);
        }


        tr:hover {
            background-color: rgba(0, 255, 65, 0.07);

        }

        .footer {
            margin-top: 30px;
            padding-top: 15px;
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-color);
            opacity: 0.7;
            border-top: 1px solid var(--border-color);
            position: relative;
        }

        .footer::before {
            content: "[SECURITY REPORT END]";
            position: absolute;
            top: -10px;
            left: 50%;
            transform: translateX(-50%);
            background-color: var(--bg-color);
            padding: 0 15px;
            font-size: 0.75rem;
            color: var(--header-color);
        }

        .terminal-scanline {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(
                to bottom,
                rgba(0, 0, 0, 0),
                rgba(0, 0, 0, 0) 50%,
                rgba(0, 0, 0, 0.02) 50%,
                rgba(0, 0, 0, 0)
            );
            background-size: 100% 4px;
            z-index: 2;
            pointer-events: none;
            animation: scanline 6s linear infinite;
        }

        a {
            color: var(--header-color);
            text-decoration: none;
            border-bottom: 1px dotted var(--header-color);
            transition: all 0.3s ease;
        }

        a:hover {
            color: var(--accent-color);
            border-bottom: 1px solid var(--accent-color);
        }

        ul {
            list-style-type: none;
            padding-left: 10px;
        }

        ul li {
            padding: 5px 0;
            position: relative;
        }

        ul li:before {
            content: ">";
            position: absolute;
            left: -15px;
            color: var(--accent-color);
        }

        .blink {
            animation: blink 1.5s infinite;
        }

        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }

        @keyframes scanline {
            0% { background-position: 0 0; }
            100% { background-position: 0 100%; }
        }

        .system-info-summary {
            background-color: rgba(0, 255, 65, 0.05);
            border: 1px solid var(--border-color);
            border-radius: 5px;
            padding: 15px;
            margin: 20px 0;
        }

        /* Responsive adjustments */
        @media screen and (max-width: 768px) {
            .terminal-container {
                padding: 10px;
            }

            th, td {
                padding: 8px;
                font-size: 0.85rem;
            }

            h2 {
                font-size: 1.4rem;
            }
        }
    </style>
</head>
<body>
<div class="terminal-scanline"></div>
<div class="terminal-container">
    <div class="terminal-header">
        <div class="terminal-title">SECURITY AUDIT: System Information & Summary</div>
        <div class="terminal-controls">
            <div class="terminal-control red"></div>
            <div class="terminal-control yellow"></div>
            <div class="terminal-control green"></div>
        </div>
    </div>
    <h2>System Information & Security Audit Summary</h2>

    <div class="system-info-summary">
        <h3>Server Information</h3>
        <table>
            <tr><td><strong>Server Name:</strong></td><td>$serverName</td></tr>
            <tr><td><strong>Audit Date:</strong></td><td>$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</td></tr>
        </table>

        $reportsLinks
        $errorSummary
    </div>
"@

        $htmlFooter = @"
<div class='footer'>
    <p>Generated on <span class="blink">$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</span></p>
    <p>User: $($env:USERNAME) | System: $($env:COMPUTERNAME)</p>
</div>
</div>
</body>
</html>
"@

        $systemHTML = $systemOverview | ConvertTo-Html -Fragment
        $diskHTML = $diskInfo | ConvertTo-Html -Fragment
        $networkHTML = $networkInfo | ConvertTo-Html -Fragment
        $avHTML = $antivirusInfo | ConvertTo-Html -Fragment

        $html = @"
$htmlHeader
<h3>System Overview</h3>
$systemHTML
<h3>Disk Information</h3>
$diskHTML
<h3>Network Information</h3>
$networkHTML
<h3>Antivirus Information</h3>
$avHTML
$htmlFooter
"@

        Set-Content -Path $Path -Value $html -Encoding UTF8
        Log-Message "System information exported successfully"
    }
    catch {
        Log-Message "Error exporting system information: $_" "Red" -IsError
        $errorData = @([PSCustomObject]@{ 'Error' = "Failed to export system information: $($_.Exception.Message)" })
        Export-ToHtml -Path $Path -InputObject $errorData -Title "System Information - Error Report"
    }
}

function Export-UserGroups {
    param (
        [string]$Path
    )

    Log-Message "Collecting user groups information..."
    try {
        if (Get-Command Get-LocalGroup -ErrorAction SilentlyContinue) {
            $groupsData = @()
            $groups = Get-LocalGroup | Sort-Object Name

            foreach ($group in $groups) {
                $groupName = $group.Name
                $members = @()

                try {
                    $members = Get-LocalGroupMember -Group $groupName -ErrorAction Stop | Select-Object Name, PrincipalSource
                }
                catch {
                    Log-Message "Error getting members for group $groupName : $_" "Yellow" -IsError
                }

                $memberList = if ($members.Count -gt 0) {
                    ($members | ForEach-Object { "$($_.Name) ($($_.PrincipalSource))" }) -join ", "
                } else {
                    "No members"
                }

                $groupsData += [PSCustomObject]@{
                    'Group Name' = $groupName
                    'Description' = $group.Description
                    'Members' = $memberList
                }
            }

            if ($groupsData.Count -gt 0) {
                Export-ToHtml -Path $Path -InputObject $groupsData -Title "User Groups"
                Log-Message "User groups information exported successfully"
            }
            else {
                $noGroups = @([PSCustomObject]@{ 'Status' = "No user groups found on this system." })
                Export-ToHtml -Path $Path -InputObject $noGroups -Title "User Groups"
                Log-Message "No user groups found" "Yellow"
            }
        }
        else {
            try {
                $wmiGroups = Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount='True'" |
                             Select-Object Name, Description, SID

                if ($wmiGroups.Count -gt 0) {
                    $formattedGroups = @()
                    foreach ($group in $wmiGroups) {
                        $formattedGroups += [PSCustomObject]@{
                            'Group Name' = $group.Name
                            'Description' = $group.Description
                            'SID' = $group.SID
                            'Members' = "Cannot retrieve members using WMI method"
                        }
                    }

                    Export-ToHtml -Path $Path -InputObject $formattedGroups -Title "User Groups (WMI Method)"
                    Log-Message "User groups information exported successfully (WMI Method)"
                }
                else {
                    $noGroups = @([PSCustomObject]@{ 'Status' = "No user groups found on this system." })
                    Export-ToHtml -Path $Path -InputObject $noGroups -Title "User Groups"
                    Log-Message "No user groups found" "Yellow"
                }
            }
            catch {
                Log-Message "Error retrieving user groups using WMI fallback: $_" "Red" -IsError
                $errorData = @([PSCustomObject]@{ 'Error' = "Failed to retrieve user groups information: $($_.Exception.Message)" })
                Export-ToHtml -Path $Path -InputObject $errorData -Title "User Groups - Error Report"
            }
        }
    }
    catch {
        Log-Message "Error exporting user groups information: $_" "Red" -IsError
        $errorData = @([PSCustomObject]@{ 'Error' = "Failed to export user groups information: $($_.Exception.Message)" })
        Export-ToHtml -Path $Path -InputObject $errorData -Title "User Groups - Error Report"
    }
}


function Check-WindowsDefender {
    param (
        [string]$Path
    )

    Log-Message "Checking Microsoft Defender settings..."
    try {
        $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        if (-not $defenderService) {
            $message = @"
<!DOCTYPE html>
<html><head><meta charset='UTF-8'><style>body{font-family:'Segoe UI';margin:20px;}h2{color:#333;}</style></head>
<body><h2>Microsoft Defender Settings</h2><p>The Windows Defender service is not installed on this system.</p></body></html>
"@
            Set-Content -Path $Path -Value $message -Encoding UTF8
            Log-Message "Windows Defender service not found" "Yellow"
            return
        }

        $defenderSettings = @()
        $defenderSettings += [PSCustomObject]@{
            Setting = "Service Status"
            Value = $defenderService.Status
            Icon = if ($defenderService.Status -eq "Running") { "good" } else { "bad" }
        }

        try {
            $mpComputerStatus = Get-CimInstance -Namespace "root/microsoft/windows/defender" -ClassName MSFT_MpComputerStatus -ErrorAction Stop

            $defenderSettings += [PSCustomObject]@{
                Setting = "Real-time Protection"
                Value = if ($mpComputerStatus.RealTimeProtectionEnabled) { "Enabled" } else { "Disabled" }
                Icon = if ($mpComputerStatus.RealTimeProtectionEnabled) { "good" } else { "bad" }
            }
            $defenderSettings += [PSCustomObject]@{
                Setting = "Cloud Protection"
                Value = if ($mpComputerStatus.IsCloudProtectionEnabled) { "Enabled" } else { "Disabled" }
                Icon = if ($mpComputerStatus.IsCloudProtectionEnabled) { "good" } else { "bad" }
            }
            $defenderSettings += [PSCustomObject]@{
                Setting = "Automatic Sample Submission"
                Value = if ($mpComputerStatus.IsAutoSampleSubmissionEnabled) { "Enabled" } else { "Disabled" }
                Icon = if ($mpComputerStatus.IsAutoSampleSubmissionEnabled) { "good" } else { "bad" }
            }
            $defenderSettings += [PSCustomObject]@{
                Setting = "Anti-virus Enabled"
                Value = if ($mpComputerStatus.AntivirusEnabled) { "Yes" } else { "No" }
                Icon = if ($mpComputerStatus.AntivirusEnabled) { "good" } else { "bad" }
            }
            $defenderSettings += [PSCustomObject]@{
                Setting = "Anti-spyware Enabled"
                Value = if ($mpComputerStatus.AntispywareEnabled) { "Yes" } else { "No" }
                Icon = if ($mpComputerStatus.AntispywareEnabled) { "good" } else { "bad" }
            }
            $defenderSettings += [PSCustomObject]@{
                Setting = "Behavior Monitor Enabled"
                Value = if ($mpComputerStatus.BehaviorMonitorEnabled) { "Yes" } else { "No" }
                Icon = if ($mpComputerStatus.BehaviorMonitorEnabled) { "good" } else { "bad" }
            }
            $defenderSettings += [PSCustomObject]@{
                Setting = "PUA Protection Enabled"
                Value = if ($mpComputerStatus.PUAProtectionEnabled) { "Yes" } else { "No" }
                Icon = if ($mpComputerStatus.PUAProtectionEnabled) { "good" } else { "bad" }
            }
            $defenderSettings += [PSCustomObject]@{
                Setting = "Network Inspection System Enabled"
                Value = if ($mpComputerStatus.NISEnabled) { "Yes" } else { "No" }
                Icon = if ($mpComputerStatus.NISEnabled) { "good" } else { "bad" }
            }
            $defenderSettings += [PSCustomObject]@{
                Setting = "Last Full Scan Time"
                Value = $mpComputerStatus.LastFullScanTime
                Icon = ""
            }
            $defenderSettings += [PSCustomObject]@{
                Setting = "Last Quick Scan Time"
                Value = $mpComputerStatus.LastQuickScanTime
                Icon = ""
            }
            $defenderSettings += [PSCustomObject]@{
                Setting = "Engine Version"
                Value = $mpComputerStatus.AMEngineVersion
                Icon = ""
            }
            $defenderSettings += [PSCustomObject]@{
                Setting = "AV Signature Version"
                Value = $mpComputerStatus.AVSignatureVersion
                Icon = ""
            }
            $defenderSettings += [PSCustomObject]@{
                Setting = "AS Signature Version"
                Value = $mpComputerStatus.ASSignatureVersion
                Icon = ""
            }
        }
        catch {
            Log-Message "Could not retrieve Defender status via CIM" "Yellow" -IsError
        }

        try {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender"
            if (Test-Path $regPath) {
                $regSettings = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($regSettings) {
                    $defenderSettings += [PSCustomObject]@{
                        Setting = "Installation Path"
                        Value = $regSettings.InstallLocation
                        Icon = ""
                    }
                    $defenderSettings += [PSCustomObject]@{
                        Setting = "Product Version"
                        Value = $regSettings.ProductVersion
                        Icon = ""
                    }
                }
            }

            $defPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates"
            if (Test-Path $defPath) {
                $sigSettings = Get-ItemProperty -Path $defPath -ErrorAction SilentlyContinue

                if ($sigSettings -and $sigSettings.SignatureLastUpdated) {
                    $lastDefUpdate = [datetime]::FromFileTime($sigSettings.SignatureLastUpdated)

                    $defenderSettings += [PSCustomObject]@{
                        Setting = "Last Definition Update"
                        Value   = $lastDefUpdate.ToString("yyyy-MM-dd HH:mm:ss")
                        Icon    = if ($lastDefUpdate -gt (Get-Date).AddDays(-7)) { "good" } else { "bad" }
                    }
                }
            }
        }
        catch {
            Log-Message "Error retrieving Defender registry information: $_" "Yellow" -IsError
        }

        if ($defenderSettings.Count -eq 0) {
            throw "No Defender settings could be retrieved"
        }

        Export-ToHtml -Path $Path -InputObject $defenderSettings -Title "Microsoft Defender Settings"
        Log-Message "Microsoft Defender settings exported successfully"
    }
    catch {
        Log-Message "Error checking Windows Defender: $_" "Red" -IsError

        $errorHtml = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset='UTF-8'>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #fff; }
        h2 { color: #333; }
        .error { color: red; padding: 10px; border: 1px solid red; background-color: #ffebee; }
        .footer { margin-top: 20px; text-align: center; font-size: 12px; color: #666; }
    </style>
</head>
<body>
<h2>Microsoft Defender Settings - Error Report</h2>
<div class="error">
    <p>Failed to retrieve Windows Defender settings: $($_.Exception.Message)</p>
    <p>Please check if Windows Defender is installed and running on this system.</p>
</div>
<div class='footer'>Generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
</body></html>
"@
        Set-Content -Path $Path -Value $errorHtml -Encoding UTF8
    }
}
# Main execution block
try {
    Log-Message "Starting security audit..."

    $securityPolicy = Get-SecurityPolicy

    $tasks = @(
        @{ Name = "GPO Settings";               Action = { Export-GPOSettings           -Path $gpoFilePath            -SecurityPolicy $securityPolicy } },
        @{ Name = "Firewall Settings";          Action = { Export-FirewallSettings      -Path $firewallConfigFilePath } },
        @{ Name = "Running Services";           Action = { Export-ServicesReport        -Path $servicesReportPath     } },
        @{ Name = "Installed Software";         Action = { Export-InstalledSoftware     -Path $installedSoftwarePath  } },
        @{ Name = "Update History";             Action = { Export-UpdateHistory         -Path $updateHistoryPath      } },
        @{ Name = "Local Users";                Action = { Export-LocalUsers            -Path $localUsersPath         } },
        @{ Name = "User Groups";                Action = { Export-UserGroups            -Path $groupMembersPath       } },
        @{ Name = "Network Connections";        Action = { Export-NetworkConnections    -Path $networkConnectionsPath } },
        @{ Name = "Password Policy";            Action = { Export-PasswordPolicy        -Path $passwordPolicyPath     -SecurityPolicy $securityPolicy } },
        @{ Name = "System Information";         Action = { Export-SystemInformation     -Path $systemInfoPath         } },
        @{ Name = "Windows Defender Settings";  Action = { Check-WindowsDefender        -Path $defenderConfigFilePath } }
    )

    foreach ($task in $tasks) {
        try {
            Log-Message "Starting task: $($task.Name)..."
            & $task.Action
            Log-Message "Completed task: $($task.Name)"
        }
        catch {
            Log-Message "Error in task $($task.Name): $_" "Red" -IsError
        }
    }
    if ($ErrorLog.Count -gt 0) {
        $errorHtml = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset='UTF-8'>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #fff; }
        h2 { color: red; }
        ul { list-style-type: disc; padding-left: 20px; }
        .footer { margin-top: 20px; text-align: center; font-size: 12px; color: #666; }
    </style>
</head>
<body>
<h2>Error Log</h2>
<ul>
"@
        foreach ($error in $ErrorLog) {
            $errorHtml += "<li>$error</li>`n"
        }
        $errorHtml += "</ul><div class='footer'>Generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div></body></html>"

        Set-Content -Path $errorLogPath -Value $errorHtml -Encoding UTF8
    }

    Log-Message "Security audit completed successfully"
    Log-Message "All reports have been saved to: $folderPath"

    if (Test-Path $tempFolderPath) {
        Remove-Item -Path $tempFolderPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    try {
        Start-Process explorer.exe -ArgumentList $folderPath
    }
    catch {
        Log-Message "Failed to open reports folder. Please navigate to: $folderPath" "Yellow" -IsError
    }
}
catch {
    Log-Message "An error occurred during the audit process: $_" "Red" -IsError
}
finally {
    if (Test-Path $tempFolderPath) {
        Remove-Item -Path $tempFolderPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

