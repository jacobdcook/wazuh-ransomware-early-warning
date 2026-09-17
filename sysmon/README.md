# Sysmon baseline

Lab Sysmon 15.x baseline for Riverbend Windows endpoints. It collects the event IDs the Wazuh ransomware pack needs and is not a general-purpose enterprise config.

What is collected: EID 1 process create, EID 3 network connect, EID 7 image load, EID 10 process access, EID 11 file create, EID 12/13 registry, EID 22 DNS. HashAlgorithms is sha256. Windows Update, Defender, and Sysmon itself are excluded.

Why each EID:
EID 1: command lines for vssadmin/wmic shadow wipe, schtasks, Defender tamper, wevtutil, encoded PowerShell, and download cradles.
EID 3: egress from script hosts and user-writable paths. Baseline only; no primary rule keys off it yet.
EID 7: DLL loads into lsass.exe and loads from Temp, Users, or AppData.
EID 10: process opens of lsass.exe and NTDS with dump-style GrantedAccess.
EID 11: ransom-note names, .locked/.encrypted/.crypt/.enc, user document writes, VSS and ntds.dit copies.
EID 12: registry key create/delete on Run, RunOnce, and Defender policy objects.
EID 13: registry value set on Run/RunOnce and Defender disable values.
EID 22: DNS from script hosts. Microsoft, Defender, and Windows Update names are dropped.

Deploy (idempotent): .\Deploy-Sysmon.ps1 -SysmonExe .\Sysmon64.exe -ConfigPath .\sysmonconfig.xml -Verify
Absent service: Sysmon -accepteula -i. Already installed: Sysmon -c. The script checks the service is Running and prints the config SHA256.

Verify events: Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5
