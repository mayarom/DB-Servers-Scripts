# MSSQL Server Audit Script - PowerShell + T-SQL
# Target: SQL Server 2016/2019
# Functions: SYSADMIN/SA check, Mixed Mode, TDE, Always Encrypted, Audit Logs, User permissions

param(
    [string]$ServerInstance = ".",
    [string]$Database = "master"
)

# Import SQL Server module
try {
    Import-Module SqlServer -ErrorAction Stop
} catch {
    Install-Module -Name SqlServer -Force -AllowClobber
    Import-Module SqlServer
}

# Initialize variables
$hostname = $env:COMPUTERNAME
$date = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outDir = "C:\Audit\$hostname`_MSSQL_$date"

# Create output directory
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

# Test connection and get version
try {
    $version = (Invoke-Sqlcmd -Query "SELECT @@VERSION as Version" ` -Encrypt Optional -TrustServerCertificate $true
        -ServerInstance $ServerInstance `
        -Database $Database `
        -Encrypt Optional `
        -TrustServerCertificate $true).Version
    Write-Host "Connected to SQL Server: $hostname"
} catch {
    Write-Host "Failed to connect to SQL Server: $($_.Exception.Message)"
    exit 1
}

Write-Host "Starting MSSQL audit - $date"
Write-Host "Output directory: $outDir"

# 1. SQL Server Version and Edition
$versionQuery = @"
SELECT
    SERVERPROPERTY('ServerName') AS ServerName,
    SERVERPROPERTY('MachineName') AS MachineName,
    SERVERPROPERTY('InstanceName') AS InstanceName,
    SERVERPROPERTY('ProductVersion') AS ProductVersion,
    SERVERPROPERTY('ProductLevel') AS ProductLevel,
    SERVERPROPERTY('Edition') AS Edition,
    SERVERPROPERTY('EngineEdition') AS EngineEdition,
    @@VERSION AS FullVersion
"@

$versionInfo = Invoke-Sqlcmd -Query $versionQuery -ServerInstance $ServerInstance -Database $Database -Encrypt Optional -TrustServerCertificate $true
$versionInfo | Export-Csv -Path "$outDir\sql_version_info.csv" -NoTypeInformation -Encoding UTF8

# 2. Authentication Mode
$authQuery = @"
SELECT
    CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
        WHEN 1 THEN 'Windows Authentication Only'
        WHEN 0 THEN 'Mixed Mode (SQL Server and Windows Authentication)'
        ELSE 'Unknown'
    END AS AuthenticationMode,
    SERVERPROPERTY('IsIntegratedSecurityOnly') AS IsWindowsAuthOnly
"@

$authMode = Invoke-Sqlcmd -Query $authQuery -ServerInstance $ServerInstance -Database $Database -Encrypt Optional -TrustServerCertificate $true
$authMode | Export-Csv -Path "$outDir\sql_authentication_mode.csv" -NoTypeInformation -Encoding UTF8

# 3. SYSADMIN and SA Users
$sysadminQuery = @"
SELECT
    p.name AS PrincipalName,
    p.type_desc AS PrincipalType,
    p.is_disabled AS IsDisabled,
    p.create_date AS CreateDate,
    p.modify_date AS ModifyDate,
    p.default_database_name AS DefaultDatabase,
    CASE WHEN IS_SRVROLEMEMBER('sysadmin', p.name) = 1 THEN 'YES' ELSE 'NO' END AS IsSysadmin,
    CASE WHEN p.name = 'sa' THEN 'YES' ELSE 'NO' END AS IsSA
FROM sys.server_principals p
WHERE p.type IN ('S', 'U', 'G')
    AND (IS_SRVROLEMEMBER('sysadmin', p.name) = 1 OR p.name = 'sa')
ORDER BY p.name
"@

$sysadminUsers = Invoke-Sqlcmd -Query $sysadminQuery -ServerInstance $ServerInstance -Database $Database -Encrypt Optional -TrustServerCertificate $true
$sysadminUsers | Export-Csv -Path "$outDir\sql_sysadmin_users.csv" -NoTypeInformation -Encoding UTF8

# 4. All Server Principals and Permissions
$usersQuery = @"
SELECT
    p.name AS UserName,
    p.type_desc AS Type,
    p.is_disabled AS IsDisabled,
    p.create_date AS CreateDate,
    p.modify_date AS ModifyDate,
    p.default_database_name AS DefaultDB,
    CASE WHEN IS_SRVROLEMEMBER('sysadmin', p.name) = 1 THEN 'YES' ELSE 'NO' END AS IsSysadmin,
    CASE WHEN IS_SRVROLEMEMBER('serveradmin', p.name) = 1 THEN 'YES' ELSE 'NO' END AS IsServeradmin,
    CASE WHEN IS_SRVROLEMEMBER('securityadmin', p.name) = 1 THEN 'YES' ELSE 'NO' END AS IsSecurityadmin,
    CASE WHEN IS_SRVROLEMEMBER('processadmin', p.name) = 1 THEN 'YES' ELSE 'NO' END AS IsProcessadmin,
    CASE WHEN IS_SRVROLEMEMBER('setupadmin', p.name) = 1 THEN 'YES' ELSE 'NO' END AS IsSetupadmin,
    CASE WHEN IS_SRVROLEMEMBER('bulkadmin', p.name) = 1 THEN 'YES' ELSE 'NO' END AS IsBulkadmin,
    CASE WHEN IS_SRVROLEMEMBER('diskadmin', p.name) = 1 THEN 'YES' ELSE 'NO' END AS IsDiskadmin,
    CASE WHEN IS_SRVROLEMEMBER('dbcreator', p.name) = 1 THEN 'YES' ELSE 'NO' END AS IsDbcreator,
    CASE WHEN IS_SRVROLEMEMBER('public', p.name) = 1 THEN 'YES' ELSE 'NO' END AS IsPublic
FROM sys.server_principals p
WHERE p.type IN ('S', 'U', 'G', 'R')
    AND p.name NOT LIKE '##%'
    AND p.name NOT LIKE 'NT %'
ORDER BY p.name
"@

$allUsers = Invoke-Sqlcmd -Query $usersQuery -ServerInstance $ServerInstance -Database $Database -Encrypt Optional -TrustServerCertificate $true
$allUsers | Export-Csv -Path "$outDir\sql_users.csv" -NoTypeInformation -Encoding UTF8

# 5. TDE Status
$tdeQuery = @"
SELECT
    d.name AS DatabaseName,
    d.database_id,
    d.is_encrypted AS IsEncryptedTDE,
    dm.encryption_state AS EncryptionState,
    CASE dm.encryption_state
        WHEN 0 THEN 'No database encryption key present'
        WHEN 1 THEN 'Unencrypted'
        WHEN 2 THEN 'Encryption in progress'
        WHEN 3 THEN 'Encrypted'
        WHEN 4 THEN 'Key change in progress'
        WHEN 5 THEN 'Decryption in progress'
        WHEN 6 THEN 'Protection change in progress'
        ELSE 'Unknown'
    END AS EncryptionStateDesc,
    dm.percent_complete AS PercentComplete,
    dm.key_algorithm AS KeyAlgorithm,
    dm.key_length AS KeyLength
FROM sys.databases d
LEFT JOIN sys.dm_database_encryption_keys dm ON d.database_id = dm.database_id
WHERE d.name NOT IN ('master', 'model', 'msdb', 'tempdb')
ORDER BY d.name
"@

try {
    $tdeStatus = Invoke-Sqlcmd -Query $tdeQuery -ServerInstance $ServerInstance -Database $Database -Encrypt Optional -TrustServerCertificate $true
    $tdeStatus | Export-Csv -Path "$outDir\sql_tde_status.csv" -NoTypeInformation -Encoding UTF8
} catch {
    Write-Host "TDE check failed: $($_.Exception.Message)"
}

# 6. Always Encrypted Status
$alwaysEncryptedQuery = @"
SELECT
    DB_NAME() AS DatabaseName,
    'Column Master Keys' AS ObjectType,
    COUNT(*) AS Count
FROM sys.column_master_keys
UNION ALL
SELECT
    DB_NAME() AS DatabaseName,
    'Column Encryption Keys' AS ObjectType,
    COUNT(*) AS Count
FROM sys.column_encryption_keys
UNION ALL
SELECT
    DB_NAME() AS DatabaseName,
    'Encrypted Columns' AS ObjectType,
    COUNT(*) AS Count
FROM sys.columns c
INNER JOIN sys.types t ON c.system_type_id = t.system_type_id
WHERE c.encryption_type IS NOT NULL AND c.encryption_type <> 0
"@

try {
    $alwaysEncrypted = Invoke-Sqlcmd -Query $alwaysEncryptedQuery -ServerInstance $ServerInstance -Database $Database -Encrypt Optional -TrustServerCertificate $true
    $alwaysEncrypted | Export-Csv -Path "$outDir\sql_always_encrypted.csv" -NoTypeInformation -Encoding UTF8
} catch {
    Write-Host "Always Encrypted check failed: $($_.Exception.Message)"
}

# 7. Server Audit Configuration
$auditQuery = @"
SELECT
    a.name AS AuditName,
    a.audit_id,
    a.type_desc AS AuditType,
    a.on_failure_desc AS OnFailure,
    a.is_state_enabled AS IsEnabled,
    a.create_date AS CreateDate,
    a.modify_date AS ModifyDate,
    af.name AS AuditFileName,
    af.max_file_size AS MaxFileSizeMB,
    af.max_rollover_files AS MaxRolloverFiles
FROM sys.server_audits a
LEFT JOIN sys.server_file_audits af ON a.audit_id = af.audit_id
UNION ALL
SELECT
    'Default Trace' AS AuditName,
    -1 as audit_id,
    'TRACE' AS AuditType,
    'Continue' AS OnFailure,
    CASE WHEN value_in_use = 1 THEN 1 ELSE 0 END AS IsEnabled,
    NULL AS CreateDate,
    NULL AS ModifyDate,
    NULL AS AuditFileName,
    NULL AS MaxFileSizeMB,
    NULL AS MaxRolloverFiles
FROM sys.configurations
WHERE name = 'default trace enabled'
"@

try {
    $auditConfig = Invoke-Sqlcmd -Query $auditQuery -ServerInstance $ServerInstance -Database $Database -Encrypt Optional -TrustServerCertificate $true
    $auditConfig | Export-Csv -Path "$outDir\sql_audit_config.csv" -NoTypeInformation -Encoding UTF8
} catch {
    Write-Host "Audit configuration check failed: $($_.Exception.Message)"
}

# 8. Default Trace Status
$traceQuery = @"
SELECT
    c.name AS ConfigurationName,
    c.value AS CurrentValue,
    c.value_in_use AS ValueInUse,
    c.description AS Description,
    CASE WHEN c.value_in_use = 1 THEN 'Enabled' ELSE 'Disabled' END AS Status
FROM sys.configurations c
WHERE c.name IN ('default trace enabled', 'c2 audit mode')
UNION ALL
SELECT
    'Default Trace File Location' AS ConfigurationName,
    REVERSE(SUBSTRING(REVERSE(path), CHARINDEX('\', REVERSE(path)), 260)) AS CurrentValue,
    1 AS ValueInUse,
    'Current default trace file location' AS Description,
    'Active' AS Status
FROM sys.traces
WHERE is_default = 1
"@

try {
    $traceStatus = Invoke-Sqlcmd -Query $traceQuery -ServerInstance $ServerInstance -Database $Database -Encrypt Optional -TrustServerCertificate $true
    $traceStatus | Export-Csv -Path "$outDir\sql_trace_status.csv" -NoTypeInformation -Encoding UTF8
} catch {
    Write-Host "Trace status check failed: $($_.Exception.Message)"
}

# 9. Database Roles and Permissions
$dbRolesQuery = @"
USE master;
SELECT
    DB_NAME() AS DatabaseName,
    p.name AS PrincipalName,
    p.type_desc AS PrincipalType,
    r.name AS RoleName,
    'Database Role Member' AS PermissionType
FROM sys.database_role_members rm
INNER JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id
INNER JOIN sys.database_principals p ON rm.member_principal_id = p.principal_id
WHERE p.name NOT LIKE '##%'
UNION ALL
SELECT
    DB_NAME() AS DatabaseName,
    dp.name AS PrincipalName,
    dp.type_desc AS PrincipalType,
    o.name AS ObjectName,
    pe.permission_name AS PermissionType
FROM sys.database_permissions pe
INNER JOIN sys.objects o ON pe.major_id = o.object_id
INNER JOIN sys.database_principals dp ON pe.grantee_principal_id = dp.principal_id
WHERE dp.name NOT LIKE '##%'
    AND pe.state_desc = 'GRANT'
ORDER BY DatabaseName, PrincipalName, PermissionType
"@

try {
    $dbRoles = Invoke-Sqlcmd -Query $dbRolesQuery -ServerInstance $ServerInstance -Database $Database -Encrypt Optional -TrustServerCertificate $true
    $dbRoles | Export-Csv -Path "$outDir\sql_database_permissions.csv" -NoTypeInformation -Encoding UTF8
} catch {
    Write-Host "Database permissions check failed: $($_.Exception.Message)"
}

# 10. Security Configuration Summary
$securitySummary = @"
SELECT
    c.name AS ConfigurationName,
    c.value AS CurrentValue,
    c.value_in_use AS ValueInUse,
    c.description AS Description,
    CASE
        WHEN c.name = 'clr enabled' AND c.value_in_use = 0 THEN 'SECURE'
        WHEN c.name = 'clr enabled' AND c.value_in_use = 1 THEN 'REVIEW'
        WHEN c.name = 'xp_cmdshell' AND c.value_in_use = 0 THEN 'SECURE'
        WHEN c.name = 'xp_cmdshell' AND c.value_in_use = 1 THEN 'RISK'
        WHEN c.name = 'remote access' AND c.value_in_use = 0 THEN 'SECURE'
        WHEN c.name = 'remote access' AND c.value_in_use = 1 THEN 'REVIEW'
        WHEN c.name = 'SQL Mail XPs' AND c.value_in_use = 0 THEN 'SECURE'
        WHEN c.name = 'SQL Mail XPs' AND c.value_in_use = 1 THEN 'REVIEW'
        WHEN c.name = 'Database Mail XPs' AND c.value_in_use = 0 THEN 'SECURE'
        WHEN c.name = 'Database Mail XPs' AND c.value_in_use = 1 THEN 'REVIEW'
        ELSE 'INFO'
    END AS SecurityStatus
FROM sys.configurations c
WHERE c.name IN (
    'clr enabled',
    'xp_cmdshell',
    'remote access',
    'SQL Mail XPs',
    'Database Mail XPs',
    'Ole Automation Procedures',
    'cross db ownership chaining',
    'default trace enabled'
)
ORDER BY SecurityStatus DESC, c.name
"@

try {
    $securityConfig = Invoke-Sqlcmd -Query $securitySummary -ServerInstance $ServerInstance -Database $Database -Encrypt Optional -TrustServerCertificate $true
    $securityConfig | Export-Csv -Path "$outDir\sql_security_config.csv" -NoTypeInformation -Encoding UTF8
} catch {
    Write-Host "Security configuration check failed: $($_.Exception.Message)"
}

# Generate Summary Report
$summaryReport = @"
MSSQL Server Security Audit Summary
===================================
Server: $hostname
Date: $date
SQL Version: $($versionInfo.ProductVersion)
Authentication Mode: $($authMode.AuthenticationMode)
SYSADMIN Users: $($sysadminUsers.Count)
Total Server Principals: $($allUsers.Count)

Files generated in: $outDir
"@

$summaryReport | Out-File -FilePath "$outDir\AUDIT_SUMMARY.txt" -Encoding UTF8

Write-Host "MSSQL audit completed"

Write-Host "Files saved to: $outDir"
