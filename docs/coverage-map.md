# Coverage map

Twelve primary Wazuh rules for ransomware early warning on a small Windows fleet. Rule IDs are fixed. Support rules `100120`–`100129` (level 0–3) may exist as frequency parents and are not counted in the twelve.

## Primary rules

| Rule ID | Technique | Name | SEV | Level | Source events (Wazuh parent) | Test case |
|---|---|---|---|---|---|---|
| 100100 | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS memory access | SEV-1 | 14 | Sysmon EID 10 (`61612`): `TargetImage` `\lsass.exe`, `GrantedAccess` `0x1010`, `0x1038`, `0x1fffff`, `0x143a` | TC-03 |
| 100101 | [T1490](https://attack.mitre.org/techniques/T1490/) | Shadow copy deletion | SEV-1 | 14 | Sysmon EID 1 (`61603`): `vssadmin delete shadows`, `wmic shadowcopy delete`, `vssadmin resize shadowstorage`, `bcdedit /set {default} recoveryenabled no`, `wbadmin delete catalog` | TC-01 v1, v2 |
| 100102 | [T1486](https://attack.mitre.org/techniques/T1486/) | Ransom note / encryption artifact written | SEV-1 | 15 (active response) | Sysmon EID 11 (`61613`): `TargetFilename` matching ransom-note names or double extensions (`.locked`, `.encrypted`, `.crypt`, `.enc`, `RANSOM_NOTE.txt`, `README_TO_DECRYPT`, `HOW_TO_RECOVER`, `DECRYPT_INSTRUCTIONS`) | TC-06 |
| 100103 | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB admin-share lateral movement | SEV-2 | 12 | Security 5140 (`60100` parent, `providerName` `Microsoft-Windows-Security-Auditing`): `ShareName` `\\*\ADMIN$` or `\\*\C$` from a non-loopback `IpAddress` | TC-04 |
| 100104 | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | PsExec-style remote service execution | SEV-2 | 12 | System 7045 (`60001` parent, `providerName` `Service Control Manager`): `ServiceName` `PSEXESVC` or `ImagePath` `%SystemRoot%\PSEXESVC.exe` or an `ImagePath` under `\\ADMIN$\` | TC-04 |
| 100105 | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry run-key persistence | SEV-2 | 12 | Sysmon EID 13 (`61615`): `TargetObject` `\CurrentVersion\Run\` or `\RunOnce\`, `Details` pointing at `\Users\`, `\Temp\`, `\AppData\`, `\ProgramData\` or a script host | TC-08 |
| 100106 | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled task creation | SEV-2 | 12 | Security 4698 (`60100` parent) or Sysmon EID 1 `schtasks /create` with `/sc` and a script host or `\Users\` path | TC-09 |
| 100107 | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Suspicious new service (non-PsExec) | SEV-2 | 12 | System 7045: `ImagePath` in `\Users\`, `\Temp\`, `\AppData\`, `\ProgramData\`, or containing `powershell`, `cmd.exe /c`, `rundll32`, `-enc` | TC-10 |
| 100108 | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Defender or logging disabled | SEV-2 | 13 | Sysmon EID 1: `Set-MpPreference -Disable*`, `Add-MpPreference -ExclusionPath`; Sysmon EID 13: `\Windows Defender\DisableAntiSpyware`, `\Real-Time Protection\DisableRealtimeMonitoring` set to 1; `auditpol /clear`, `Stop-Service -Name Sysmon` | TC-11 |
| 100109 | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Windows event log cleared | SEV-2 | 13 | Security 1102 (`60100` parent), System 104 (`60001` parent), Sysmon EID 1 `wevtutil cl` / `Clear-EventLog` | TC-02 |
| 100110 | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Encoded or obfuscated PowerShell | SEV-3 | 10 | Sysmon EID 1: `-enc`, `-e `, `-EncodedCommand`, `FromBase64String`, `-w hidden`, `-nop -ep bypass`; PowerShell/Operational 4104 (`91800` group `windows_powershell`) `ScriptBlockText` with the same markers | TC-05 |
| 100111 | [T1105](https://attack.mitre.org/techniques/T1105/) | Download cradle / ingress tool transfer | SEV-3 | 10 | Sysmon EID 1: `Invoke-WebRequest`, `iwr `, `DownloadString`, `DownloadFile`, `Net.WebClient`, `certutil -urlcache`, `certutil.exe -urlcache -split -f`, `bitsadmin /transfer`, `curl.exe -o`, `Start-BitsTransfer` | TC-12 |

Example support pair (not in the twelve): `100120` is a single Sysmon EID 11 write to a user document path (level 3). `100121` correlates 30 matches of `100120` in 60 seconds on the same `win.system.computer` and fires at level 15 so it can also trigger host isolation.

## SEV to Wazuh level

| SEV | Wazuh level | Routing |
|---|---|---|
| SEV-1 | 14–15 | Immediate notification. Level 15 also drives active response. |
| SEV-2 | 12–13 | Immediate notification. |
| SEV-3 | 10–11 | Daily triage queue, not paging. |

Active response is bound only to level 15 (rules `100102` and `100121`), local to the agent, with an allowlist for the Wazuh manager IP and the management subnet.

## Sysmon event IDs and Wazuh parent SIDs

Parent IDs come from the stock Wazuh 4.x ruleset (`0595-win-sysmon_rules.xml`, `0575-win-base_rules.xml`, `0580-win-security_rules.xml`, `0915-win-powershell_rules.xml`). Custom rules chain with `<if_sid>` (or `<if_group>` for PowerShell).

| Source | Event | Stock parent | Notes |
|---|---|---|---|
| Sysmon | EID 1 Process Create | `61603` | Command-line detections (shadow copy, schtasks, Defender tamper, wevtutil, encoded PowerShell, download cradles) |
| Sysmon | EID 3 Network Connect | `61605` | Collected in the Sysmon baseline; no primary rule keys off it yet |
| Sysmon | EID 7 Image Load | `61609` | Baseline only |
| Sysmon | EID 10 Process Access | `61612` | LSASS dumpers (`100100`) |
| Sysmon | EID 11 File Create | `61613` | Ransom notes and encrypted extensions (`100102`), mass-write support (`100120`) |
| Sysmon | EID 12 Registry object | `61614` | Baseline only |
| Sysmon | EID 13 Registry value set | `61615` | Run keys (`100105`), Defender disable values (`100108`) |
| Sysmon | EID 22 DNS query | `61644` | Baseline only |
| Windows (any eventchannel JSON) | n/a | `60000` | Base decoder parent |
| Security | 5140, 4698, 1102, others | `60100` | Admin shares, scheduled tasks, log cleared |
| System | 7045, 104 | `60001` | New service, log cleared |
| PowerShell/Operational | 4104 | group `windows_powershell` (`91800` family) | Use `<if_group>windows_powershell</if_group>`, not a hard-coded SID |

## Parent SID caveat

Confirm every parent ID with `/var/ossec/bin/wazuh-logtest` on the Wazuh version that is actually deployed. Stock rule IDs drift between releases. If a custom rule never fires in lab, check that the decoded event still matches the parent SID (or `windows_powershell` group) before changing field regexes.

## What each rule misses

- **100100** misses direct-syscall dumpers and `MiniDumpWriteDump` called from a trusted signed process. Access masks outside `0x1010` / `0x1038` / `0x1fffff` / `0x143a` (including some `PROCESS_QUERY_INFORMATION`-only opens) also slip through.
- **100101** misses `Get-WmiObject Win32_ShadowCopy | Remove-WmiObject` and the CIM equivalent until a later task extends the matcher. Renamed copies of `vssadmin`/`wmic` and `diskshadow` are also out of scope.
- **100102** misses encryption that keeps original filenames and extensions. Notes written under custom names (`.html`, `.hta`, operator-chosen filenames) that are not in the list will not fire.
- **100103** ignores loopback `IpAddress` on purpose. It does not see IPC$-only traffic, 5145-only share access, or admin-share use that never logs 5140 under the host's audit policy.
- **100104** misses renamed PsExec service names, Impacket `smbexec`/`wmiexec` that never drop `PSEXESVC`, and cousins such as PAExec or CSExec.
- **100105** misses Run keys whose `Details` point at signed paths under Program Files, plus persistence that is not Run/RunOnce (COM hijack, Winlogon, IFEO).
- **100106** misses tasks created through the Task Scheduler COM API or `Register-ScheduledTask` when the Sysmon command line has no `schtasks /create /sc`. Signed actions under Program Files are out of scope.
- **100107** misses a new service whose `ImagePath` is a LOLBin under System32, or an MSI that installs into Program Files. `PSEXESVC` is owned by 100104, not this rule.
- **100108** misses Defender tamper via GPO, WMI, or a tamper-protection bypass that never sets the watched registry values or command-line flags. `sc stop WinDefend` and `fltmc unload` without the listed strings are not covered.
- **100109** misses `.NET EventLog.Clear` from a compiled binary, `wevtutil` with unusual quoting or a copied binary name, and Security 1100 (event log service shutdown).
- **100110** misses obfuscation that never uses `-enc` / `-EncodedCommand` / `FromBase64String` / `-w hidden` / `-nop -ep bypass` (token splitting, GZip+IEX, many Invoke-Obfuscation variants). Script blocks that never land in 4104 with those markers are silent.
- **100111** misses `Invoke-RestMethod`, browser-driven downloads, `certutil -decode` of a local file, and split-process transfers (download in one PID, write in another).
