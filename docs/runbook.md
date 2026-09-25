# Incident response runbook

Riverbend Managed IT Services lab. Use this pack on the Ubuntu 22.04 Wazuh 4.x manager and the Windows agents in this repo. Roles are placeholders only: `[On-call Analyst]`, `[Operations Manager]`, `[Backup Admin]`, `[Owner]`. Dashboard searches are Wazuh 4.x Threat Hunting (OpenSearch query string). Level 12-15 pages immediately. Level 10-11 goes to the daily triage queue. Host isolation is local firewall AR on level 15 only (`100102`, `100121`). Coverage and gaps: [coverage-map.md](coverage-map.md). Pocket list: [quick-reference-card.md](quick-reference-card.md). IR policy: [policies/incident-response.md](policies/incident-response.md).

## 1 Detect and triage

Owner this hour: `[On-call Analyst]`. Page `[Operations Manager]` if the first hit is SEV-1 or level 15.

Wazuh dashboard filters (paste in Threat Hunting):

```
rule.groups:ransomware AND rule.level >= 12
rule.id:(100100 OR 100101 OR 100102 OR 100121)
rule.groups:ransomware AND rule.level:[10 TO 11]
```

Rule IDs this step cares about: `100100` (LSASS), `100101`/`100122` (shadow copy), `100102`/`100121` (encryption / mass write), `100103`-`100109` (SEV-2 page), `100110`/`100111` (SEV-3 queue).

1. `[On-call Analyst]` opens Threat Hunting with `rule.groups:ransomware AND rule.level >= 12`. Treat `100100`, `100101`, `100102`, and `100121` as page-now. Park `rule.id:(100110 OR 100111)` on the daily queue.
2. Record `agent.name`, `data.win.system.computer`, `rule.id`, `rule.level`, `@timestamp` (UTC), and `data.win.eventdata.user` if present. Lab names: `WS-FIN-02`, `WS-OPS-07`, `SRV-FILE-01`, `SRV-DC-01`.
3. Compare the command line / path to the TC-07 known-benign list on [quick-reference-card.md](quick-reference-card.md) (`wuauclt` / `usoclient` / `TiWorker`, `vssadmin list shadows`, `wbadmin start backup`, `C:\Program Files\RMM\`, loopback `ADMIN$`, Defender `MsMpEng.exe` with `0x1400`).
4. If one SEV-1 fires, or two different SEV-2 rule IDs fire on the same computer within 15 minutes, continue at section 2. Otherwise leave a queue note and stop.

Stop and escalate if: `rule.level:15` (`100102` or `100121`), or `100100` and `100101` on the same `agent.name` in one hour.

## 2 Confirm and scope

Owner: `[On-call Analyst]`. Brief `[Operations Manager]` before any isolation decision. `[Owner]` is copied if `SRV-DC-01` appears.

Wazuh dashboard filters (replace the agent/computer with the alerting host):

```
agent.name:WS-FIN-02 AND rule.groups:ransomware
data.win.system.computer:WS-FIN-02 AND rule.id:(100100 OR 100101 OR 100102 OR 100103 OR 100104 OR 100121)
rule.id:(100103 OR 100104) AND NOT data.win.eventdata.ipAddress:(127.0.0.1 OR ::1)
```

Rule IDs this step uses: `100100`-`100111` plus support `100121`/`100122`. Pivot on computer, then on user, then on admin-share / PsExec.

1. `[On-call Analyst]` opens the raw event and confirms it is not a TC-07 near-miss (`wevtutil qe` vs `cl`, `vssadmin list` vs `delete`, signed `-File` under `C:\Program Files\`). If it matches the known-benign list, close as false positive and file a rule-change note per [policies/detection-rule-change-standard.md](policies/detection-rule-change-standard.md).
2. Scope the same `data.win.system.computer` for the rest of the chain: encoded PowerShell `100110`, download cradle `100111`, LSASS `100100`, admin share `100103`, `PSEXESVC` `100104`, run key `100105`, schtask `100106`, odd service `100107`, Defender tamper `100108`, log clear `100109`.
3. Repeat the filter on `SRV-FILE-01`, `SRV-DC-01`, and `WS-OPS-07`. `100103`/`100104` on a second host means lateral movement, not a single-box problem.
4. Hand `[Operations Manager]` a three-line brief: hosts, rule IDs, whether level 15 already isolated the agent. Do not contain yet unless section 3 criteria are met.

Stop and escalate if: more than one lab host is in the hit set, `SRV-DC-01` is in the hit set, or the same user shows `100103` plus `100104`.

## 3 Contain

Owner: `[Operations Manager]` authorizes. `[On-call Analyst]` executes. `[Owner]` must approve anything that would isolate `SRV-DC-01`. `[Backup Admin]` is notified but does not restore during this section.

Wazuh dashboard filters:

```
rule.id:(100102 OR 100121) AND rule.level:15
rule.groups:ransomware AND data.win.system.computer:WS-FIN-02 AND rule.level:15
```

Rule IDs that drive isolation: `100102` (ransom note / `.locked` write, Sysmon EID 11) and `100121` (30 user-document writes in 60 seconds). AR config: [../wazuh/active-response/ar-config.snippet.xml](../wazuh/active-response/ar-config.snippet.xml). Procedure: [../wazuh/active-response/README.md](../wazuh/active-response/README.md).

1. `[Operations Manager]` checks whether `C:\ProgramData\ossec-agent\isolation.json` already exists on the alerting agent (AR may have fired). If yes, skip to step 3. If no, and `100102` or `100121` is confirmed, authorize a manual isolate.
2. `[On-call Analyst]` on the manager (lab VM with console access to the agent): `/var/ossec/bin/agent_control -L` then `/var/ossec/bin/agent_control -b AGENT_IP -f isolate-host0`. Confirm manager IPv4 still has TCP 1514/1515 and the management CIDR still has inbound 3389/5985.
3. On the agent, confirm firewall group `RansomwareIsolation` and the marker file. Isolation is host-wide block with those two holes only. It does not kill processes and it does not stop encryption already in flight.
4. Do not isolate `SRV-DC-01` or the only jump box without `[Owner]` plus hypervisor console. Wrong `ManagerIp` / `MgmtCidr` strands the host.

Stop and escalate if: AR did not fire within 60 seconds of a confirmed `100102`/`100121`, isolation is already on and a second host still writes `.locked` files, or the marker exists but 1514 to the manager is dead.

## 4 Eradicate

Owner: `[On-call Analyst]` on the isolated host. `[Operations Manager]` approves persistence removal. `[Backup Admin]` snapshots first. `[Owner]` is informed if a service or task name is unknown.

Wazuh dashboard filters:

```
rule.id:(100105 OR 100106 OR 100107 OR 100108 OR 100109)
agent.name:WS-FIN-02 AND rule.id:(100105 OR 100106 OR 100107)
rule.id:100104 AND data.win.eventdata.serviceName:PSEXESVC
```

Rule IDs this step hunts: `100105` (Run/RunOnce), `100106` (`schtasks /create`), `100107` (user/temp/script-host service), `100104` (`PSEXESVC`), `100108` (Defender/Sysmon/auditpol tamper), `100109` (log clear). Gaps are in [coverage-map.md](coverage-map.md).

1. `[Backup Admin]` takes a hypervisor snapshot of the isolated VM before anyone deletes a service, task, or Run key. Do not use VSS on a host that already fired `100101`.
2. `[On-call Analyst]` lists the matching persistence from the alerts (TargetObject for `100105`, task name for `100106`, ImagePath for `100107`/`100104`) and removes only those objects on the isolated host.
3. If `100108` fired, re-enable Defender real-time monitoring and Sysmon, and restore audit policy. If `100109` fired, treat logs on that host as incomplete and pull Sysmon from the manager copy.
4. Re-run the section 2 computer filter. Persistence that reappears after removal is a second implant, not a leftover.

Stop and escalate if: `PSEXESVC` or a user-path service appears on a second host, persistence returns after removal, or `[On-call Analyst]` cannot map an ImagePath to an alert.

## 5 Recover

Owner: `[Backup Admin]` for data. `[Operations Manager]` authorizes rollback of isolation. `[On-call Analyst]` watches the dashboard. `[Owner]` accepts residual risk if backups are older than the first `100110`/`100111`.

Wazuh dashboard filters:

```
rule.groups:ransomware AND rule.level >= 12 AND @timestamp:[now-24h TO now]
rule.id:(100102 OR 100121) AND agent.name:WS-FIN-02
rule.id:100101 AND data.win.system.computer:SRV-FILE-01
```

Rule IDs this step uses: `100101` (VSS gone; do not trust local shadow copies), `100102`/`100121` (encryption still active?), `100100`-`100111` for a 30-minute quiet window after restore.

1. `[Backup Admin]` identifies the last backup taken before the first precursor (`100110`/`100111` if present, else `100100`/`100103`). If `100101` fired, discard local shadow copies and restore from off-host backup only.
2. Restore the affected files or VM to a clean volume. Do not decrypt `.locked` files in place. Simulator lab files roll back with `python3 simulator/encrypt_sim.py --rollback` (files only, not the firewall).
3. After `[Operations Manager]` says the host is clean enough to talk to the LAN, `[On-call Analyst]` runs the isolation rollback one-liner elevated:

```
powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files (x86)\ossec-agent\active-response\bin\isolate-host.ps1" -Rollback
```

4. Watch Threat Hunting for 30 minutes with `agent.name:<restored-host> AND rule.groups:ransomware`. Zero new `100102`/`100121` before handing the host back.

Stop and escalate if: no backup exists from before the first precursor, restore target starts writing `.locked` or `RANSOM_NOTE.txt`, or `-Rollback` does not restore ping/RDP/WinRM from the management CIDR.

## 6 Communicate

Owner: `[Operations Manager]` drives status. `[On-call Analyst]` supplies timestamps and rule IDs. `[Backup Admin]` supplies restore ETA. `[Owner]` is the only role that talks outside the lab team.

Wazuh dashboard filters (status snapshot, same query each update):

```
rule.groups:ransomware AND rule.level >= 12
rule.id:(100100 OR 100101 OR 100102 OR 100103 OR 100104 OR 100121)
```

Rule IDs to quote in every update: the IDs that actually fired, with level and host. Do not claim 12/12 coverage from a live incident unless the export shows `100100`-`100111`.

1. `[On-call Analyst]` writes a UTC timeline: first `100110`/`100111` (if any), then credential/lateral (`100100`/`100103`/`100104`), then `100101`, then `100102`/`100121`, plus isolation and rollback times.
2. `[Operations Manager]` sends that timeline to `[Owner]` with current containment state (isolated / rolled back / not isolated) and the TC-07 check result.
3. `[Owner]` decides what Riverbend staff outside this lab hear. This repo is a fictitious-org capstone lab: there is no customer notification list in git. Do not put real people or student IDs in the ticket.
4. Updates go on a fixed clock (every 30 minutes while level 15 is open, then once at restore). Use the same dashboard filter so counts are comparable.

Stop and escalate if: a second site/host appears after the first status mail, backups will miss RPO, or anyone asks to disable `100102`/`100121` to "keep the business up" without a written exception.

## 7 Post-incident

Owner: `[On-call Analyst]` drafts. `[Operations Manager]` tracks actions. `[Backup Admin]` confirms restore integrity. `[Owner]` closes the incident.

Wazuh dashboard filters (export this search; it is the evidence set):

```
rule.groups:ransomware AND rule.id:(100100 OR 100101 OR 100102 OR 100103 OR 100104 OR 100105 OR 100106 OR 100107 OR 100108 OR 100109 OR 100110 OR 100111 OR 100120 OR 100121 OR 100122)
```

Rule IDs that must be accounted for: every primary ID `100100`-`100111` either fired, or has an honest miss bullet in [coverage-map.md](coverage-map.md). Support `100120`-`100122` are extra.

1. `[On-call Analyst]` exports the filter above and diffs it against [../docs/test-plan.md](test-plan.md) acceptance bars (12/12 in the designed chain, TC-07 = 0, isolation ≤ 60 s, rollback restores connectivity).
2. `[Operations Manager]` opens a detection change if a true positive missed a rule or a false positive hit TC-07-class activity. Follow [policies/detection-rule-change-standard.md](policies/detection-rule-change-standard.md): sample event, pytest, coverage-map bullet.
3. `[Backup Admin]` records backup age vs first precursor and whether `100101` made local VSS unusable. `[On-call Analyst]` adds any new benign sample under `tests/sample_events/TC-07/` if a false positive was confirmed.
4. `[Owner]` signs the close note only after rollback is proven, restore is proven, and the action list has owners. Then update this runbook if a numbered step was skipped or failed.

Stop and escalate if: a primary rule missed a true positive that is not already listed under "What each rule misses" in [coverage-map.md](coverage-map.md), or pytest is red after the detection change.
