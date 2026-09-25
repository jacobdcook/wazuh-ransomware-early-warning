# Incident response policy

Lab policy for ransomware precursor and encryption-behavior alerts produced by this pack. Procedure detail is in [../runbook.md](../runbook.md). Pocket list: [../quick-reference-card.md](../quick-reference-card.md).

## Purpose

Detect, confirm, contain, eradicate, recover, communicate, and review incidents that match rules `100100`-`100111` (and level-15 support `100121`) on the Riverbend lab Windows fleet, without pretending this is a 24/7 SOC or a legal notification program.

## Scope

In scope: hosts that run this repo's Sysmon baseline, Wazuh agent eventchannel config, and (for containment) the `isolate-host` active response. Fictitious accounts (`jdoe`, `svc_backup`, `rmm_agent`) and hosts (`WS-FIN-02`, `WS-OPS-07`, `SRV-FILE-01`, `SRV-DC-01`) are the lab namespace.

Out of scope: real customers, law enforcement filing, ransomware-payment decisions, and malware reverse engineering. Isolation is a Windows firewall group (`RansomwareIsolation`), not process kill and not network ACL on the switch.

## Requirements

1. Follow the seven runbook sections in order. Do not skip Confirm and scope to jump to Contain unless `rule.level:15` already isolated the agent.
2. Page on Wazuh level 12-15. Queue level 10-11 (`100110`, `100111`) for the same calendar day. Do not page on support `100120` (level 3).
3. Active response is bound only to `100102` and `100121` (level 15, `<location>local</location>`, no timeout). Manual isolate uses `/var/ossec/bin/agent_control -b AGENT_IP -f isolate-host0` from the manager, with console access to the agent.
4. Rollback is manual and documented:

```
powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files (x86)\ossec-agent\active-response\bin\isolate-host.ps1" -Rollback
```

5. Evidence: UTC timestamps, `rule.id`, `agent.name`, `isolation.json`, and `pytest -q` if a rule change is part of the fix. Honest gaps stay in [../coverage-map.md](../coverage-map.md).
6. Do not disable `100102`/`100121` during an open incident except under Exceptions below.

## Roles

- `[On-call Analyst]`: first dashboard search, scoping, persistence removal, rollback execution, post-incident export.
- `[Operations Manager]`: isolation authorization, status clock, detection follow-ups.
- `[Backup Admin]`: snapshots before eradicate, restore from off-host backup when `100101` has killed VSS.
- `[Owner]`: isolation of `SRV-DC-01` or the only jump box; closeout; any exception that weakens a SEV-1 rule.

## Review cadence

After every isolation event (AR or `agent_control`): `[Operations Manager]` checks the 60-second bar from first `100102`/`100121` Sysmon EID 11 to `isolation.json`, and that `-Rollback` restored management-CIDR RDP/WinRM.

After every incident close: walk [../runbook.md](../runbook.md) section 7 and [../test-plan.md](../test-plan.md) acceptance bars.

Quarterly: tabletop the summative chain TC-05 → TC-12 → TC-03 → TC-04 → TC-01 → TC-06 on two lab hosts. TC-07 must still be zero.

## Exceptions

`[Owner]` may delay isolation on `SRV-DC-01` until hypervisor console is confirmed. `[Owner]` may grant a written 24-hour pause of AR for a named agent during a restore window; the pause is a manager `ossec.conf` change with expiry, not a deleted rule. Payment, disclosure, and production legal holds are out of scope: if a scenario needs them, stop the lab exercise and write that in the close note.
