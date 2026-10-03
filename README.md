# Wazuh ransomware early-warning lab

Riverbend Managed IT Services, the hostnames in this repo, and every account name used in samples are fictitious. This is a detection-engineering lab for a WGU MS Cybersecurity capstone. Counts and timings come from an isolated lab against Atomic Red Team cases and the bundled simulator. Nothing here was measured on a production network.

[![tests](https://github.com/jacobdcook/wazuh-ransomware-early-warning/actions/workflows/tests.yml/badge.svg)](https://github.com/jacobdcook/wazuh-ransomware-early-warning/actions/workflows/tests.yml) pytest 58 passed · 12 rules · MIT

This pack is a Wazuh 4.x plus Sysmon early-warning set for a small Windows fleet. It pages on ransomware precursors (LSASS access, shadow-copy deletion, admin-share hops, encryption artifacts) rather than after the fleet is already locked. Tests are offline pytest against synthetic decoded events. They do not need a Wazuh install, Windows, or a network.

Sequel to [blue-team-soc-monitoring-lab](https://github.com/jacobdcook/blue-team-soc-monitoring-lab) (Linux `auth.log` brute force). Same author, now Windows, Sysmon, and ransomware.

## Coverage (short)

Twelve primary rules, IDs 100100–100111. Full table, parent SIDs, SEV map, and per-rule gaps: [docs/coverage-map.md](docs/coverage-map.md).

| ID | Technique | Name | SEV | Lvl |
|---|---|---|---|---|
| 100100 | T1003.001 | LSASS memory access | 1 | 14 |
| 100101 | T1490 | Shadow copy deletion | 1 | 14 |
| 100102 | T1486 | Ransom note / encryption artifact | 1 | 15 (AR) |
| 100103 | T1021.002 | SMB admin-share lateral movement | 2 | 12 |
| 100104 | T1569.002 | PsExec-style remote service | 2 | 12 |
| 100105 | T1547.001 | Registry run-key persistence | 2 | 12 |
| 100106 | T1053.005 | Scheduled task creation | 2 | 12 |
| 100107 | T1543.003 | Suspicious new service | 2 | 12 |
| 100108 | T1562.001 | Defender or logging disabled | 2 | 13 |
| 100109 | T1070.001 | Windows event log cleared | 2 | 13 |
| 100110 | T1059.001 | Encoded or obfuscated PowerShell | 3 | 10 |
| 100111 | T1105 | Download cradle / ingress | 3 | 10 |

Level 15 (`100102`, support `100121`) can isolate the host. Level ≥ 12 pages. Level 10–11 goes to the daily queue.

| Claim | Evidence |
|---|---|
| Twelve ATT&CK-mapped Wazuh rules (IDs 100100–100111) | [wazuh/rules/local_rules.xml](wazuh/rules/local_rules.xml) |
| Pytest harness and synthetic events for every rule | [tests/](tests/) |
| Firewall host-isolation active response with rollback | [wazuh/active-response/](wazuh/active-response/) |
| Benign encryption-behavior simulator | [simulator/encrypt_sim.py](simulator/encrypt_sim.py) |
| Incident runbook | [docs/runbook.md](docs/runbook.md) |

## Quickstart

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
python3 simulator/encrypt_sim.py --target ./simulator_sandbox --files 20
python3 simulator/encrypt_sim.py --target ./simulator_sandbox --rollback
```

Expect `58 passed` from `pytest -q` (see [VERIFICATION.md](VERIFICATION.md)). The simulator only writes under an empty directory or a prior simulator workspace. It refuses `.git`, `C:\Windows`, filesystem root, and the home root. `--rollback` restores the `.txt` files and removes `RANSOM_NOTE.txt` plus `*.locked`.

## Layout

```
.
├── README.md
├── LICENSE
├── VERIFICATION.md
├── requirements.txt
├── docs/
│   ├── ransomware-detection-refresh.html
│   ├── coverage-map.md
│   ├── runbook.md
│   ├── install-guide.md
│   ├── tuning.md
│   ├── test-plan.md
│   ├── quick-reference-card.md
│   └── policies/
├── wazuh/
│   ├── rules/          local_rules.xml
│   ├── agent/          ossec.conf.snippet.xml
│   └── active-response/ isolate-host.ps1, isolate-host.cmd
├── sysmon/             sysmonconfig.xml, Deploy-Sysmon.ps1
├── simulator/          encrypt_sim.py
└── tests/
    ├── test_*.py
    ├── atomic/         TC-01.yaml … TC-12.yaml
    └── sample_events/  TC-01 … TC-12 (TC-07 is the zero-alert set)
```

## Read next

1. Teaching page: [docs/ransomware-detection-refresh.html](docs/ransomware-detection-refresh.html) (kill chain, three public incident TLDRs, per-rule cards, interview lines, self-quiz).
2. Analyst runbook: [docs/runbook.md](docs/runbook.md) (detect through post-incident, with role placeholders).
