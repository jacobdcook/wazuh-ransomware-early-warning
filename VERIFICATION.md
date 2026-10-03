# Verification record

Date: 2026-10-02 (UTC timestamp from this run: `Sat Oct  3 12:52:13 AM UTC 2026`).

Commands below ran in this git checkout on a Linux workstation. They did not run on a Wazuh manager, a Windows agent, or Sysmon. Deployment steps in [docs/install-guide.md](docs/install-guide.md) are procedure only.

## `pytest -q`

Working directory: repository root. Command: `python3 -m pytest -q`.

```
...........................................                              [100%]
43 passed in 0.11s
```

Exit status 0. Forty-three tests. No network. No Wazuh install. No Windows.

## `xmllint --noout` on each XML file

Four tracked `.xml` files. Each command exited 0 with empty stdout and empty stderr.

```
xmllint --noout sysmon/sysmonconfig.xml
xmllint --noout wazuh/rules/local_rules.xml
xmllint --noout wazuh/agent/ossec.conf.snippet.xml
xmllint --noout wazuh/active-response/ar-config.snippet.xml
```

Each file has a single root (`<Sysmon>`, `<group>`, or `<ossec_config>`).

## `python3 -m py_compile`

Nine tracked `.py` files. Each command exited 0 with empty stdout and empty stderr.

```
python3 -m py_compile tests/__init__.py
python3 -m py_compile tests/conftest.py
python3 -m py_compile tests/rule_engine.py
python3 -m py_compile tests/test_rules.py
python3 -m py_compile tests/test_simulator.py
python3 -m py_compile tests/test_atomic_map.py
python3 -m py_compile tests/test_docs.py
python3 -m py_compile tests/test_sysmon.py
python3 -m py_compile simulator/encrypt_sim.py
```

## Not yet verified on live Wazuh

A live Ubuntu 22.04 all-in-one manager plus four Windows agents would still need to prove:

1. The 4.x installer (`wazuh-install.sh -a`) completes on 8 vCPU / 16 GB / 500 GB, and dashboard 1443 or 443 plus API 55000 answer from the analyst station.
2. Ports 1514/tcp (events) and 1515/tcp (enrollment) accept the lab agents.
3. `sudo cp wazuh/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml` and `systemctl restart wazuh-manager` load rules `100100`–`100111` and `100120`–`100122`.
4. Stock parent SIDs on that Wazuh build still match [docs/coverage-map.md](docs/coverage-map.md) (`61603`, `61612`, `61613`, `61615`, `60100`, `60001`, group `windows_powershell`). Confirm with `/var/ossec/bin/wazuh-logtest`, including the smoke-test JSON in the install guide (expect `100101` level 14, not only parent `61603`).
5. Agent MSI install with `WAZUH_MANAGER` (and the `agent-auth` fallback) shows `WS-FIN-02`, `WS-OPS-07`, `SRV-FILE-01`, `SRV-DC-01` as Active.
6. Pasting the four eventchannel `<localfile>` blocks from `wazuh/agent/ossec.conf.snippet.xml` delivers Sysmon/Operational, PowerShell/Operational, Security, and System events.
7. `Deploy-Sysmon.ps1 -Verify` on Sysmon 15.x: service Running, config hash printed, `Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5` returns events.
8. Active response: `isolate-host.cmd` / `isolate-host.ps1` on the agent, `ar-config.snippet.xml` merged on the manager with a real manager IP and management CIDR, `agent_control -b` creates `RansomwareIsolation` and `C:\ProgramData\ossec-agent\isolation.json`, and `isolate-host.ps1 -Rollback` restores connectivity.
9. Formative Atomic / simulator runs: 12/12 primary rules fire on live hosts; TC-07 produces zero live alerts (pytest TC-07 is offline only). TC-06 run from `C:\Users\labuser\Documents\simulator_sandbox` raises `100121` as well as `100102`.
10. Summative chain on two hosts (TC-05 → TC-12 → TC-03 → TC-04 → TC-01 → TC-06): isolation within 60 seconds of TC-06, rollback restores connectivity. Bars are in [docs/test-plan.md](docs/test-plan.md).
11. Alert routing in operations: level ≥ 12 pages; level 10–11 sits on the daily queue; the > 15 alerts/day for a week trigger in [docs/tuning.md](docs/tuning.md) is measured from live `rule.id` counts, not from this file.
12. Sysmon 15.x accepts the full-path ProcessAccess exclusions (`is` plus the `begin with`/`end with` Defender platform rules), the real `MsMpEng.exe` under `C:\ProgramData\Microsoft\Windows Defender\Platform\<version>\` stays silent, and a copy of `csrss.exe` run from `C:\Users\Public\` against lsass is logged as EID 10. `tests/test_sysmon.py` emulates this offline only.

Nothing in this record claims those eleven items were executed.
