# Tuning notes

## Gap found in testing: shadow copy deletion via WMI cmdlets

Rule 100101 originally matched only the classic recovery-tamper command lines: `vssadmin delete shadows`, `wmic shadowcopy delete`, `vssadmin resize shadowstorage`, `bcdedit /set {default} recoveryenabled no`, and `wbadmin delete catalog`. That first regex does not fire on PowerShell WMI or CIM deletion. Those command lines never contain `vssadmin` or the token sequence `wmic` + `shadowcopy delete`.

The miss showed up on synthetic TC-01 traffic shaped like:

- `Get-WmiObject Win32_ShadowCopy | Remove-WmiObject`
- `Get-CimInstance Win32_ShadowCopy | Remove-CimInstance`
- `Win32_ShadowCopy` in the same text as a `.Delete()` call

Fix: extend 100101 `win.eventdata.commandLine` (Sysmon EID 1, parent `61603`) with those three forms. Add sibling rule 100122 for PowerShell/Operational 4104 (`<if_group>windows_powershell</if_group>`) on `win.eventdata.scriptBlockText`, same technique (T1490) and level 14. Query-only WMI (`Get-WmiObject Win32_ShadowCopy` with no `Remove-*` or `Delete()`) still does not match. Backup `vssadmin list shadows` in TC-07 is unchanged.

Regression test path: `tests/sample_events/TC-01/v3_powershell_wmi.json` and `test_tc01_v3_powershell_wmi_missed_by_legacy_regex` in `tests/test_rules.py`. That test compiles the original command-line regex, asserts every v3 sample misses it, and asserts the current ruleset returns 100101 on Sysmon EID 1 and 100122 on 4104.

## Volume trigger: more than 15 alerts per day for a week

Any primary rule (`100100`–`100111`) that averages more than 15 alerts per day across seven consecutive days gets an exclusion review. Support rules `100120`–`100122` are in scope if they are the reason a host isolates (`100121`) or if `100120` is drowning the indexer.

This is a review trigger, not an automatic mute. Count from the Wazuh dashboard (`rule.id` over the last 7d, divide by 7). `[On-call Analyst]` files the review. `[Operations Manager]` owns the rule change. Policy: [policies/monitoring-and-log-management.md](policies/monitoring-and-log-management.md) and [policies/detection-rule-change-standard.md](policies/detection-rule-change-standard.md).

Do not hide `100102` or `100121` with a dashboard filter. Level 15 isolation stays bound to those IDs.

## Exclusion-pattern method

Permanent excludes are rules-as-code in [../wazuh/rules/local_rules.xml](../wazuh/rules/local_rules.xml) plus a benign sample under `tests/sample_events/TC-07/`. The pytest emulator loads every `TC-*/*.json` file; `test_tc07_zero_alerts` fails if any of those events match a primary rule.

Preferred pattern (tighten the matcher):

1. Pull one live (or reconstructed) decoded event: `win.system.eventID`, `win.system.providerName`, `win.eventdata.image`, `commandLine` / `targetFilename` / `user` / `parentImage`.
2. Confirm it is benign: signed path under `C:\Program Files\`, known lab user `svc_backup` or `rmm_agent`, and it is not a true-positive command (`vssadmin delete shadows`, `wevtutil cl`, `-EncodedCommand`, and the rest of [coverage-map.md](coverage-map.md)).
3. Narrow the existing `type="pcre2"` field so that event no longer `re.search`es, without dropping the malicious samples in `tests/sample_events/TC-01` … `TC-06` and `TC-08` … `TC-12`. Typical levers: require `delete` not `list`, require `\Users\` / `\Temp\` not `\Program Files\`, require dump masks `0x1010`/`0x1038`/`0x1fffff`/`0x143a` not Defender `0x1400`.
4. Add a TC-07 JSON file that is a copy of the noisy event with `"expect": {"rule_id": null}` (steps below).
5. Run `pytest -q`. Malicious TCs must still fire. TC-07 must stay zero. Update the "What each rule misses" bullet in [coverage-map.md](coverage-map.md) if the miss list changed.

Fallback pattern (level-0 child, only if tightening the primary regex would miss a true positive): add a support rule in `100123`–`100129` with `<if_sid>` of the noisy parent, `level="0"`, and `type="pcre2"` fields that match the benign `user` + `parentImage` (or equivalent). Keep the primary regex. The pytest emulator still evaluates primary rules first in `test_tc07_zero_alerts` via `match()` on each primary, so a level-0 child does not hide a primary hit in this harness. If the benign event still matches the primary, tighten the primary anyway; the level-0 child is for a live manager only after the primary no longer matches. Do not use IDs outside `100120`–`100129`.

Never: empty `<description>`, dropping a `def test_`, deleting a primary ID, or muting by dashboard.

## Example: backup agent (`svc_backup`)

[../tests/sample_events/TC-07/backup_agent.json](../tests/sample_events/TC-07/backup_agent.json) is the known-benign pair:

- Host `SRV-FILE-01`, user `RIVERBEND\svc_backup`, parent `C:\Program Files\RiverbendBackup\agent.exe`
- `vssadmin list shadows` (Sysmon EID 1)
- `wbadmin start backup -backupTarget:E: -include:C: -quiet`

Rule `100101` requires `vssadmin` + `delete shadows` (or `resize shadowstorage`), `wmic` + `shadowcopy delete`, `wbadmin` + `delete catalog`, or the WMI/CIM remove forms. `list shadows` and `start backup` do not match. Leave that gap; it is the exclusion.

If a backup product starts emitting `vssadmin delete shadows` as part of rotation, that is a true-positive-shaped command. Do not exclude `delete`. If a new backup binary's command line contains `shadowcopy` next to `delete` without being `wmic`, tighten `100101` to keep requiring `wmic` as the image or the `wmic ... shadowcopy delete` token sequence, then add the new command line as a TC-07 file.

`[Backup Admin]` is the role that confirms the product path and the exact command line before `[On-call Analyst]` edits XML.

## Example: RMM (`rmm_agent`)

[../tests/sample_events/TC-07/rmm_health.json](../tests/sample_events/TC-07/rmm_health.json) is the known-benign pair:

- Host `WS-OPS-07`, user `RIVERBEND\rmm_agent`, parent `C:\Program Files\RMM\rmm-host.exe`
- `powershell.exe -File C:\Program Files\RMM\health.ps1`
- `powershell.exe -ExecutionPolicy Bypass -File C:\Program Files\RMM\inventory.ps1`

Rule `100110` keys on `-enc`, `-e `, `-EncodedCommand`, `FromBase64String`, `-w hidden`, and `-nop -ep bypass`. `-ExecutionPolicy Bypass` alone from `C:\Program Files\RMM\` is out of scope on purpose. `100111` keys on download cradles (`Invoke-WebRequest`, `certutil -urlcache`, and the rest), not `-File` of a local signed script.

If RMM later launches `powershell.exe -nop -ep bypass -File C:\Program Files\RMM\health.ps1`, `100110` will fire. Exclusion: add a negative lookahead on `commandLine` for `\\Program Files\\RMM\\` only when `-File` points at that directory, or require `-enc` / `FromBase64String` for that path. Then drop the new command line into TC-07 as below. Do not exclude `-EncodedCommand` from an RMM-named process that lives under `\Users\` or `\Temp\`.

## How to add a benign sample to TC-07

The harness in [../tests/conftest.py](../tests/conftest.py) loads every `tests/sample_events/TC-*/*.json` as a JSON list. `test_tc07_zero_alerts` in [../tests/test_rules.py](../tests/test_rules.py) requires at least ten TC-07 events, each with `"expect": {"rule_id": null}`, and asserts `evaluate(event, rules)` is `None` and no primary rule `match()`es. [../tests/atomic/TC-07.yaml](../tests/atomic/TC-07.yaml) must keep `expected_rule_ids: []`.

1. Write a new file `tests/sample_events/TC-07/<short_name>.json`. Do not overwrite `backup_agent.json` or `rmm_health.json`.
2. Use a JSON list of Wazuh-decoded events. Minimum shape (one event):

```
[
  {
    "win": {
      "system": {
        "eventID": "1",
        "providerName": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "SRV-FILE-01"
      },
      "eventdata": {
        "image": "C:\\Windows\\System32\\vssadmin.exe",
        "commandLine": "vssadmin list shadows",
        "parentImage": "C:\\Program Files\\RiverbendBackup\\agent.exe",
        "user": "RIVERBEND\\svc_backup"
      }
    },
    "expect": {
      "rule_id": null
    }
  }
]
```

3. Hostnames only: `WS-FIN-02`, `WS-OPS-07`, `SRV-FILE-01`, `SRV-DC-01`. Domain `RIVERBEND`. Users `jdoe`, `svc_backup`, `rmm_agent`. Field names stay camelCase (`commandLine`, `parentImage`, `targetFilename`, and the rest used in `wazuh/rules/local_rules.xml`).
4. Copy the noisy field values from the live alert, not a cleaned-up guess. If the exclusion is a path, the sample must include that path.
5. Apply the XML change first (or in the same edit). If `pytest -q` then fails `test_tc07_zero_alerts`, the exclusion is not done.
6. Confirm a malicious sibling still fires (for backup noise, `tests/sample_events/TC-01/` must still return `100101`). `test_malicious_tcs_have_at_least_two_firing_events` must stay green.
7. Do not invent MITRE GUIDs. Do not add the sample under TC-01 … TC-06; those directories are for events that must alert.

Existing TC-07 files to leave in place: `backup_agent.json`, `rmm_health.json`, `windows_update.json`, `wevtutil_query.json`, `defender_lsass.json`, `loopback_admin_share.json`, `software_deploy.json`, `runkey_programfiles.json`, `normal_document_write.json`.
