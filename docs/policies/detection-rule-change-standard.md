# Detection rule change standard

How Riverbend lab detection rules in this repository change without silent false positives or missing tests. Monitoring volume trigger: [monitoring-and-log-management.md](monitoring-and-log-management.md). IR use of those rules: [incident-response.md](incident-response.md).

## Purpose

Keep `wazuh/rules/local_rules.xml` aligned with [../coverage-map.md](../coverage-map.md) and with pytest samples, so a regex edit cannot ship unless a test can fail.

## Scope

In scope: primary rules `100100`-`100111`, support rules `100120`-`100129` that actually exist in XML (today `100120`, `100121`, `100122`), their `<field type="pcre2">` matchers, MITRE IDs, levels, groups, active-response bindings, synthetic events under `tests/sample_events/`, and Atomic YAML under `tests/atomic/`.

Out of scope: stock Wazuh parent SIDs (`61603`, `61612`, `60100`, and the rest). Those IDs are confirmed with `wazuh-logtest` on the deployed version, not rewritten here.

## Requirements

1. Every primary rule keeps a unique ID in `100100`-`100111`, a `<mitre><id>`, a non-empty `<description>`, `type="pcre2"` on every `<field>`, and a `ransomware,sev1|sev2|sev3,` group. SEV map is fixed: SEV-1 = level 14-15, SEV-2 = 12-13, SEV-3 = 10-11.
2. Do not renumber. Do not bind active response to anything except level 15 (`100102`, `100121`).
3. A matcher change ships with: (a) at least one JSON event that the new regex must hit, (b) TC-07 still producing zero alerts, (c) an updated "What each rule misses" bullet if the miss list changed, (d) `tests/atomic/TC-*.yaml` `expected_rule_ids` still valid.
4. An exclusion for known-benign traffic (backup `vssadmin list shadows`, RMM under `C:\Program Files\RMM\`, Windows Update, Defender `MsMpEng.exe` / `0x1400`, loopback `ADMIN$`) is a tighter regex plus a new file in `tests/sample_events/TC-07/`, not a dashboard hide.
5. Gate: `pytest -q` and `xmllint --noout wazuh/rules/local_rules.xml`. Tests make no network calls and do not need a Wazuh install.
6. Parent SID drift is handled by confirming stock IDs on the manager, then editing `<if_sid>` / `<if_group>` if Wazuh 4.x changed them. Record the confirmed IDs in coverage-map.

## Roles

- `[On-call Analyst]`: writes the sample event and the regex; runs pytest.
- `[Operations Manager]`: merges the change to the manager `/var/ossec/etc/rules/local_rules.xml` and restarts `wazuh-manager`.
- `[Backup Admin]`: not in the change path unless a rule edit is part of incident recover.
- `[Owner]`: approves emergency disable (see Exceptions) and any level change that would start or stop paging or AR.

## Review cadence

Every merged rule change: pytest + xmllint + coverage-map diff for IDs.

Weekly: any rule averaging more than 15 alerts/day for seven days is reviewed for exclusion or for a missed benign sample (TC-07).

Quarterly: `[Operations Manager]` checks that coverage-map IDs and `local_rules.xml` IDs still match (enforced by `tests/test_docs.py`) and that AR `<rules_id>` is still `100102,100121`.

## Exceptions

Emergency disable of a noisy rule: `[Owner]` may comment out or raise the matcher to a dead pattern for at most 24 hours, with a ticket and a TC-07 (or new) sample that reproduces the noise. The rule ID stays reserved. Deleting a primary ID, dropping below 12 primary rules, or removing a `def test_` is not an exception. Inventing a MITRE GUID is not allowed; Atomic refs stay "see atomic-red-team Txxxx test N" when the GUID is unknown.
