# Quick reference card

Riverbend lab, one page. Full procedure: [runbook.md](runbook.md). Gaps: [coverage-map.md](coverage-map.md).

## Who to call

- `[On-call Analyst]`: dashboard, scope, isolate/rollback hands-on
- `[Operations Manager]`: authorize isolation, status clock
- `[Backup Admin]`: snapshot, restore (not local VSS after `100101`)
- `[Owner]`: `SRV-DC-01` / jump-box isolation, closeout, 24 h AR pause

Page on Wazuh level 12-15. Queue level 10-11 the same day. AR only on level 15.

## Dashboard (Threat Hunting)

```
rule.groups:ransomware AND rule.level >= 12
rule.id:(100102 OR 100121) AND rule.level:15
```

## Twelve rules by SEV

SEV-1 (level 14-15, page now; 15 isolates):

| ID | Lvl | Name |
|---|---|---|
| 100100 | 14 | LSASS memory access |
| 100101 | 14 | Shadow copy deletion (`100122` on 4104) |
| 100102 | 15 | Ransom note / `.locked` write |

SEV-2 (level 12-13, page):

| ID | Lvl | Name |
|---|---|---|
| 100103 | 12 | SMB admin share (`ADMIN$`/`C$`, non-loopback) |
| 100104 | 12 | PsExec-style `PSEXESVC` |
| 100105 | 12 | Run / RunOnce to user/temp/script |
| 100106 | 12 | `schtasks /create` + script host or `\Users\` |
| 100107 | 12 | New service in user/temp/script-host path |
| 100108 | 13 | Defender or logging disabled |
| 100109 | 13 | Event log cleared |

SEV-3 (level 10-11, daily queue, no page):

| ID | Lvl | Name |
|---|---|---|
| 100110 | 10 | Encoded / obfuscated PowerShell |
| 100111 | 10 | Download cradle / ingress |

Support (not in the twelve): `100120` mass-write parent (level 3); `100121` burst (level 15, isolates).

## Known-benign (TC-07, must be zero alerts)

- Windows Update: `wuauclt`, `usoclient`, `TiWorker`
- Backup `svc_backup`: `vssadmin list shadows`, `wbadmin start backup` (not delete)
- RMM `rmm_agent`: signed `-File C:\Program Files\RMM\health.ps1`
- Software deploy: service ImagePath under `C:\Program Files\`
- PowerShell `-ExecutionPolicy Bypass -File` from `C:\Program Files\` (signed)
- `wevtutil qe` (query, not `cl`)
- Defender `MsMpEng.exe` opening LSASS with `0x1400`
- Loopback `ADMIN$` (`127.0.0.1` / `::1`)
- Run key whose Details point at Program Files
- Normal user document write (not `.locked` / ransom-note names)

Samples: [../tests/sample_events/TC-07/](../tests/sample_events/TC-07/).

## Isolation rollback (elevated on the host)

```
powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files (x86)\ossec-agent\active-response\bin\isolate-host.ps1" -Rollback
```

Manual isolate (manager): `/var/ossec/bin/agent_control -b AGENT_IP -f isolate-host0`. Group `RansomwareIsolation`. Marker `C:\ProgramData\ossec-agent\isolation.json`.
