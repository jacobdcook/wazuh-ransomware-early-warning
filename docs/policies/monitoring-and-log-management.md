# Monitoring and log management policy

Lab policy for Riverbend Managed IT Services. It governs how this Wazuh 4.x + Sysmon pack is collected, retained, and reviewed. It is not a production MSP contract.

## Purpose

Keep Windows process, file, registry, share, service, Defender, and PowerShell evidence complete enough for rules `100100`-`100111` (and support `100120`-`100122`) to fire, and complete enough for the runbook to scope an incident without trusting a host that already cleared its own logs (`100109`).

## Scope

In scope: the single-node Ubuntu 22.04 Wazuh 4.x manager (8 vCPU / 16 GB / 500 GB, ports 1514/tcp events, 1515/tcp enrollment, 1443 or 443 dashboard, 55000 API), Sysmon 15.x with [../../sysmon/sysmonconfig.xml](../../sysmon/sysmonconfig.xml), and Windows lab agents `WS-FIN-02`, `WS-OPS-07`, `SRV-FILE-01`, `SRV-DC-01` using [../../wazuh/agent/ossec.conf.snippet.xml](../../wazuh/agent/ossec.conf.snippet.xml).

Out of scope: cloud SaaS telemetry, Linux auth.log (that is the sibling lab), and any host that is not running this repo's Sysmon baseline and eventchannel snippet.

## Requirements

1. Each Windows agent ships four eventchannel blocks: `Microsoft-Windows-Sysmon/Operational`, `Microsoft-Windows-PowerShell/Operational`, `Security`, and `System`. The Security query keeps 4624, 4625, 4648, 4688, 4698, 4720, 4732, 5140, 5145, 1102 and drops 4634, 4658, 4663, 5156, 5158.
2. Sysmon collects EID 1, 3, 7, 10, 11, 12, 13, 22 as in the bundled config. Agents enroll with `agent-auth` or the MSI `WAZUH_MANAGER` property.
3. Custom rules live in [../../wazuh/rules/local_rules.xml](../../wazuh/rules/local_rules.xml). Parent SIDs (`61603`, `61612`, `61613`, `61615`, `60100`, `60001`, group `windows_powershell`) must be confirmed with `/var/ossec/bin/wazuh-logtest` on the deployed Wazuh version.
4. Alert routing: level 12-15 is immediate notification; level 10-11 (`100110`, `100111`) is the daily triage queue. Level 15 (`100102`, `100121`) may isolate the agent.
5. Manager disk is sized for 500 GB in this lab. Do not claim a production retention SLA. Keep alerts and archives until the next scheduled review (see cadence). Do not commit live archives to git.
6. Time is UTC on manager and agents. Hostnames and the `RIVERBEND` domain in samples are fictitious.

## Roles

- `[On-call Analyst]`: daily queue for level 10-11; confirms agents are active; files volume exceptions.
- `[Operations Manager]`: owns manager health, rule deployment, and the > 15 alerts/day/week trigger.
- `[Backup Admin]`: manager VM snapshots and evidence export during incidents ([../runbook.md](../runbook.md)).
- `[Owner]`: accepts residual risk when a log source is disabled on a lab host.

## Review cadence

Weekly: `[On-call Analyst]` checks each primary rule's alert count for the last seven days. Any rule averaging more than 15 alerts/day for a week gets an exclusion review (method in [../tuning.md](../tuning.md)), a TC-07 sample if the traffic is benign, and a change under [detection-rule-change-standard.md](detection-rule-change-standard.md).

After every manager or agent config change: `xmllint --noout` on XML, `pytest -q` in this repo, and a `wazuh-logtest` sample for one SEV-1 event.

Quarterly: `[Operations Manager]` re-reads this policy and the eventchannel query, and confirms Sysmon still hashes sha256 and the listed EIDs.

## Exceptions

Temporary log-source disable (Sysmon, Security 5140, PowerShell 4104) requires `[Owner]` plus an expiry no longer than 24 hours. Stopping Sysmon is itself a `100108`/`100109` concern. Permanent excludes are rules-as-code: a field regex change, a new TC-07 JSON file, and a coverage-map bullet. There is no silent dashboard filter that hides `100102` or `100121`.
