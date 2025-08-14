# Security Script Execution Guide

> Complete instructions and requirements for executing security scripts across different platforms and components

---

## Table of Contents

- [Windows Platforms](#windows-platforms)
- [Linux Distributions](#linux-distributions) 
- [Database Systems](#database-systems)
- [Output Structure](#output-structure)
- [Best Practices](#best-practices)

---

## Windows Platforms

### Windows Server 2008–2012

| **Component** | **Details** |
|---------------|-------------|
| **Script** | `WindowsServer2008-2012.ps1` |
| **Requirements** | PowerShell 5.1, Administrator privileges |
| **Execution** | See below |

```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process
& "C:\Path\To\WindowsServer2008-2012.ps1"
```

### Windows Server 2012 and Above

| **Component** | **Details** |
|---------------|-------------|
| **Script** | `WindowsServer2012+.ps1` |
| **Requirements** | PowerShell 5.1 or newer, Administrator privileges |
| **Execution** | See below |

```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process
& "C:\Path\To\WindowsServer2012+.ps1"
```

---

## Linux Distributions

### Red Hat Enterprise Linux 6–7

| **Component** | **Details** |
|---------------|-------------|
| **Script** | `RedHatEnterpriseLinux6-7.sh` |
| **Requirements** | Root/sudo access |
| **Execution** | See below |

```bash
chmod +x RedHatEnterpriseLinux6-7.sh
sudo ./RedHatEnterpriseLinux6-7.sh
```

### Red Hat Enterprise Linux 8–9

| **Component** | **Details** |
|---------------|-------------|
| **Script** | `RedHatEnterpriseLinux8-9.sh` |
| **Requirements** | Root/sudo access |
| **Execution** | See below |

```bash
chmod +x RedHatEnterpriseLinux8-9.sh
sudo ./RedHatEnterpriseLinux8-9.sh
```

### Ubuntu 16.04–18.04

| **Component** | **Details** |
|---------------|-------------|
| **Script** | `Ubuntu16-18.04.sh` |
| **Requirements** | Root/sudo access |
| **Execution** | See below |

```bash
chmod +x Ubuntu16-18.04.sh
sudo ./Ubuntu16-18.04.sh
```

### Ubuntu 20.04–24.04

| **Component** | **Details** |
|---------------|-------------|
| **Script** | `Ubuntu20.24.04.sh` |
| **Requirements** | Root/sudo access |
| **Execution** | See below |

```bash
chmod +x Ubuntu20.24.04.sh
sudo ./Ubuntu20.24.04.sh
```

---

## Database Systems

### PostgreSQL 11 / 13 / 15

| **Component** | **Details** |
|---------------|-------------|
| **Script** | `PostgreSQL111315.sh` |
| **Requirements** | `psql` command available, access configured (e.g., `.pgpass`) |
| **Execution** | See below |

```bash
chmod +x PostgreSQL111315.sh
./PostgreSQL111315.sh
```

### SQL Server 2016–2019

| **Component** | **Details** |
|---------------|-------------|
| **Script** | `MSSQLServer201619.ps1` |
| **Requirements** | PowerShell + SqlServer module, DBA permissions |
| **Execution** | See below |

<div style="border: 2px solid red; padding: 10px; background-color: #ffe6e6;"> <strong style="color:red;">Note:</strong> The original script failed with <code>The target principal name is incorrect</code> due to a TLS certificate name mismatch. The fix added <code>-Encrypt Optional -TrustServerCertificate $true</code> to all <code>Invoke-Sqlcmd</code> calls, allowing the script to run even when the certificate name does not match the server name. </div>



### MongoDB 4.x / 6.x

| **Component** | **Details** |
|---------------|-------------|
| **Script** | `MongoDB4x6x.sh` |
| **Requirements** | `mongo` CLI installed and in `$PATH` |
| **Execution** | See below |

```bash
chmod +x MongoDB4x6x.sh
./MongoDB4x6x.sh
```

---

## Output Structure

### Folder Naming Convention

Each script generates an output folder with the following naming pattern:

```
<hostname>_<version>_<date>
```

**Example:**
```
srv-app01_Ubuntu20_24_2025-07-31_14-12-00
```

### Output Locations

| **Platform** | **Default Location** |
|--------------|---------------------|
| **Linux** | `/tmp/` |
| **Windows** | Current working directory |

### Output Files

Each output folder contains:
- **CSV files** - Structured audit data
- **TXT files** - Detailed audit results and logs

---

## Best Practices

### Privilege Requirements

> **Important:** Always run scripts with appropriate elevated privileges

- **Linux:** Use `sudo` for system-level audits
- **Windows:** Launch PowerShell as Administrator

### Environment Setup

#### Linux Systems
```bash
# Set language environment if needed
export LANG=en_US.UTF-8
```

#### Windows Systems
```powershell
# Launch PowerShell as Administrator from Start Menu
# Right-click PowerShell → "Run as Administrator"
```

---

*Last updated: July 31, 2025*
