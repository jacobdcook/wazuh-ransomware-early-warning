# Wazuh ransomware early-warning lab

Riverbend Managed IT Services, the hostnames in this repo, and every account name used in samples are fictitious. This is a detection-engineering lab for a WGU MS Cybersecurity capstone. Counts and timings come from an isolated lab against Atomic Red Team cases and the bundled simulator. Nothing here was measured on a production network.

## Purpose

This repository ships a Wazuh 4.x and Sysmon early-warning pack for a small Windows fleet. It covers twelve ATT&CK-mapped rules, a Sysmon baseline, agent eventchannel config, a firewall host-isolation active response with rollback, a benign encryption-behavior simulator, a pytest harness against synthetic Sysmon and Windows events, and an incident runbook. The pack is meant to page on ransomware precursors (LSASS access, shadow-copy deletion, admin-share hops, encryption artifacts) rather than after the fleet is already locked.

Sequel to [blue-team-soc-monitoring-lab](https://github.com/jacobdcook/blue-team-soc-monitoring-lab) (Linux `auth.log` brute force). Same author, now Windows, Sysmon, and ransomware.

## Claim and evidence

Paths below are the intended homes for later lab artifacts. Empty until those tasks land.

| Claim | Evidence |
|---|---|
| Twelve ATT&CK-mapped Wazuh rules (IDs 100100–100111) | `wazuh/rules/local_rules.xml` |
| Pytest harness and synthetic events for every rule | `tests/` |
| Firewall host-isolation active response with rollback | `wazuh/active-response/` |
| Benign encryption-behavior simulator | `simulator/encrypt_sim.py` |
| Incident runbook | `docs/runbook.md` |

Technique coverage, parent rule IDs, and per-rule gaps: [docs/coverage-map.md](docs/coverage-map.md).

## Quickstart

```
pytest -q
```

Install test dependencies with `pip install -r requirements.txt` first. The harness and sample events are added in a later task. Until then this command has nothing to run.
