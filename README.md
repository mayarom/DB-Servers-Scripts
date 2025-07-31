# Security Script Execution Guide

This document contains full instructions and requirements for executing each security script based on the target platform or component.

---

## Windows Server 2008–2012

- **Script:** `WindowsServer2008-2012.ps1`
- **Requirements:** PowerShell 5.1, Administrator privileges
- **Execution:**
  ```powershell
  Set-ExecutionPolicy RemoteSigned -Scope Process
  & "C:\Path\To\WindowsServer2008-2012.ps1"
  ```

---

## Windows Server 2012 and Above

- **Script:** `WindowsServer2012+.ps1`
- **Requirements:** PowerShell 5.1 or newer, Administrator privileges
- **Execution:**
  ```powershell
  Set-ExecutionPolicy RemoteSigned -Scope Process
  & "C:\Path\To\WindowsServer2012+.ps1"
  ```

---

## SQL Server 2016–2019

- **Script:** `MSSQLServer201619.ps1`
- **Requirements:** PowerShell + SQLPS module, DBA permissions
- **Execution:**
  ```powershell
  Set-ExecutionPolicy RemoteSigned -Scope Process
  & "C:\Path\To\MSSQLServer201619.ps1"
  ```

---

## Red Hat Enterprise Linux 6–7

- **Script:** `RedHatEnterpriseLinux6-7.sh`
- **Execution:**
  ```bash
  chmod +x RedHatEnterpriseLinux6-7.sh
  sudo ./RedHatEnterpriseLinux6-7.sh
  ```

---

## Red Hat Enterprise Linux 8–9

- **Script:** `RedHatEnterpriseLinux8-9.sh`
- **Execution:**
  ```bash
  chmod +x RedHatEnterpriseLinux8-9.sh
  sudo ./RedHatEnterpriseLinux8-9.sh
  ```

---

## Ubuntu 16.04–18.04

- **Script:** `Ubuntu16-18.04.sh`
- **Execution:**
  ```bash
  chmod +x Ubuntu16-18.04.sh
  sudo ./Ubuntu16-18.04.sh
  ```

---

## Ubuntu 20.04–24.04

- **Script:** `Ubuntu20.24.04.sh`
- **Execution:**
  ```bash
  chmod +x Ubuntu20.24.04.sh
  sudo ./Ubuntu20.24.04.sh
  ```

---

## PostgreSQL 11 / 13 / 15

- **Script:** `PostgreSQL111315.sh`
- **Requirements:** `psql` command available; access configured (e.g., .pgpass)
- **Execution:**
  ```bash
  chmod +x PostgreSQL111315.sh
  ./PostgreSQL111315.sh
  ```

---

## MongoDB 4.x / 6.x

- **Script:** `MongoDB4x6x.sh`
- **Requirements:** `mongo` CLI must be installed and in `$PATH`
- **Execution:**
  ```bash
  chmod +x MongoDB4x6x.sh
  ./MongoDB4x6x.sh
  ```

---

## Output Folder Convention

Each script generates an output folder under `/tmp` (Linux) or the working directory (Windows) in the format:
```
<hostname>_<version>_<date>
```
Example:
```
srv-app01_Ubuntu20_24_2025-07-31_14-12-00
```

Each folder includes relevant CSV and TXT files containing the audit results.

---

## General Recommendations

- Always run scripts with appropriate privileges (sudo/Admin).
- On Linux, set language environment if needed:
  ```bash
  export LANG=en_US.UTF-8
  ```
- On Windows, launch PowerShell as Administrator.