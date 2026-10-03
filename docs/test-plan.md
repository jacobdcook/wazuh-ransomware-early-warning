# Test plan

Formative checks prove each rule in isolation. Summative checks prove the precursor-to-encryption chain and host isolation on two lab Windows hosts. Commands live in `tests/atomic/TC-01.yaml` … `TC-12.yaml`. Synthetic events in `tests/sample_events/` are the pytest stand-in so this pack can be regression-tested without a Wazuh install.

## Formative (per-TC unit tests)

Run on one Windows lab host that already has this repo's Sysmon baseline and Wazuh agent. After each case, confirm the rule IDs in `expected_rule_ids` appear in the Wazuh dashboard (filter `rule.id`) and that `pytest -q` still passes on the Linux manager or a checkout of this repo.

| TC | Host command source | Expected primary rule | Pytest |
|---|---|---|---|
| TC-01 | Atomic `T1490` test 1 (`vssadmin.exe delete shadows /all /quiet`); also tests 2 and 5 | 100101 (level 14). PowerShell 4104 WMI/CIM forms also raise sibling 100122 | `tests/sample_events/TC-01/` |
| TC-02 | Atomic `T1070.001` test 1 (`wevtutil.exe cl Security`) | 100109 (level 13) | `tests/sample_events/TC-02/` |
| TC-03 | Atomic `T1003.001` test 1 (ProcDump `-ma lsass.exe`) | 100100 (level 14) | `tests/sample_events/TC-03/` |
| TC-04 | Atomic `T1021.002` test 1 plus `T1569.002` test 2 (`psexec.exe \\SRV-FILE-01 -accepteula cmd`) | 100103 and 100104 (level 12) | `tests/sample_events/TC-04/` |
| TC-05 | Atomic `T1059.001` test 15 (`powershell.exe -EncodedCommand …`) | 100110 (level 10) | `tests/sample_events/TC-05/` |
| TC-06 | custom simulator (`python encrypt_sim.py --target C:\Users\labuser\Documents\simulator_sandbox --files 50`) | 100102 and burst 100121 (level 15). Target must stay under a local `Documents` folder or 100121 cannot fire | `tests/sample_events/TC-06/` |
| TC-07 | Benign set (start with `vssadmin.exe list shadows`) | none (`expected_rule_ids: []`) | `tests/sample_events/TC-07/` (≥ 10 events, zero alerts) |
| TC-08 | Atomic `T1547.001` test 1 with a `\Users\` Temp payload | 100105 (level 12) | `tests/sample_events/TC-08/` |
| TC-09 | Atomic `T1053.005` test 1 / lab `schtasks /create /sc` + `\Users\` | 100106 (level 12) | `tests/sample_events/TC-09/` |
| TC-10 | Atomic `T1543.003` test 1 or `sc.exe create` under `\Users\` | 100107 (level 12) | `tests/sample_events/TC-10/` |
| TC-11 | Atomic `T1562.001` test 19 (`Set-MpPreference -DisableRealtimeMonitoring`) | 100108 (level 13) | `tests/sample_events/TC-11/` |
| TC-12 | Atomic `T1105` test 7 (`certutil.exe -urlcache -split -f`) | 100111 (level 10) | `tests/sample_events/TC-12/` |

Cleanup commands are in each YAML `cleanup` field. TC-01 and TC-02 are not reversible; use a snapshot. TC-06 file rollback is `encrypt_sim.py --rollback`. Isolation rollback is separate (`isolate-host.ps1 -Rollback`).

`tests/test_atomic_map.py` checks the YAML map itself: every file parses, every `expected_rule_ids` entry exists in `wazuh/rules/local_rules.xml`, every primary ID 100100–100111 is expected by at least one TC, and TC-07 expects `[]`.

## Summative (end-to-end chain, two hosts)

Hosts: `WS-FIN-02` (beachhead) and `SRV-FILE-01` (file server / lateral target). Domain `RIVERBEND`. Do not skip cleanup between formative runs and this chain; start from a clean snapshot so timestamps are unambiguous.

Order (precursor tooling → ingress → credential access → lateral movement → inhibit recovery → encryption):

1. **TC-05** on `WS-FIN-02` (encoded PowerShell, 100110).
2. **TC-12** on `WS-FIN-02` (certutil download cradle, 100111).
3. **TC-03** on `WS-FIN-02` (LSASS dump, 100100). If the lab DC is in scope, repeat on `SRV-DC-01` only after confirming console access.
4. **TC-04** from `WS-FIN-02` to `SRV-FILE-01` (ADMIN$ + PSEXESVC, 100103 and 100104).
5. **TC-01** on `SRV-FILE-01` (shadow copy deletion, 100101).
6. **TC-06** on `WS-FIN-02` (simulator, 100102, isolation).

Watch the Wazuh dashboard during the chain. Level 10–11 (100110, 100111) belong on the daily triage queue, not a page. Level 12–14 should notify. Level 15 (100102, and 100121 if the write burst is dense enough) must launch `isolate-host` on the alerting agent.

After the chain, run the TC-07 set on both hosts. Those commands must add zero new alerts.

## Acceptance bars

- **12/12 primary rules fire.** Across formative Atomic/simulator runs plus pytest samples, IDs 100100–100111 each appear at least once. Support IDs 100120–100122 do not count toward this bar.
- **TC-07 = 0.** No primary (or support) rule matches the benign set. Pytest `test_tc07_zero_alerts` is the offline proof; the live hosts are the deployed proof.
- **Isolation within 60 s of TC-06.** Time from the first Sysmon EID 11 for `RANSOM_NOTE.txt` or `*.locked` on `WS-FIN-02` to `C:\ProgramData\ossec-agent\isolation.json` existing and firewall group `RansomwareIsolation` present. Budget is 60 seconds (agent buffer + AR).
- **Rollback restores connectivity.** On the isolated host, elevated: `powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files (x86)\ossec-agent\active-response\bin\isolate-host.ps1" -Rollback`. Then ping a non-manager address, RDP or WinRM from the management CIDR, and confirm `isolation.json` is gone. Simulator `--rollback` restores files; it does not restore the firewall.

Fail the run if any bar is missed. Do not tune a rule to silence a true positive from this chain. If TC-07 fires, that is a false positive: record the event, then fix via `docs/tuning.md` and a new TC-07 sample (later tasks).

## Evidence to capture

Save under a local, gitignored folder (for example `logs/` on the analyst station). Do not commit secrets or real host dumps.

| Artifact | What to record |
|---|---|
| Pytest | Full `pytest -q` output from this repo (offline formative). |
| Atomic / simulator | Host, UTC time, YAML `id`, exact `command`, exit code. |
| Wazuh alerts | JSON (or dashboard export) for each of 100100–100111, including `agent.name`, `rule.level`, `@timestamp`. |
| Sysmon | EID 1 / 10 / 11 / 13 (and Security 5140 / 4698 / 1102, System 7045 / 104) that correspond to each TC. |
| Isolation | `isolation.json` contents (timestamp + triggering rule id), `active-responses.log` lines, and a screenshot or `netsh advfirewall` listing of group `RansomwareIsolation`. |
| Timing | First TC-06 EID 11 timestamp vs isolation marker timestamp (must be ≤ 60 s). |
| Rollback | Ping/RDP/WinRM before isolate, while isolated, and after `-Rollback`. File hashes before/after `encrypt_sim.py --rollback`. |
| TC-07 | Alert search for the two hosts in the TC-07 window showing zero hits on 100100–100111. |
| Gaps | Anything that did not fire (renamed binaries, signed Program Files paths) with a pointer to the matching "what it misses" bullet in `docs/coverage-map.md`. |
