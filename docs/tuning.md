# Tuning notes

## Gap found in testing: shadow copy deletion via WMI cmdlets

Rule 100101 originally matched only the classic recovery-tamper command lines: `vssadmin delete shadows`, `wmic shadowcopy delete`, `vssadmin resize shadowstorage`, `bcdedit /set {default} recoveryenabled no`, and `wbadmin delete catalog`. That first regex does not fire on PowerShell WMI or CIM deletion. Those command lines never contain `vssadmin` or the token sequence `wmic` + `shadowcopy delete`.

The miss showed up on synthetic TC-01 traffic shaped like:

- `Get-WmiObject Win32_ShadowCopy | Remove-WmiObject`
- `Get-CimInstance Win32_ShadowCopy | Remove-CimInstance`
- `Win32_ShadowCopy` in the same text as a `.Delete()` call

Fix: extend 100101 `win.eventdata.commandLine` (Sysmon EID 1, parent `61603`) with those three forms. Add sibling rule 100122 for PowerShell/Operational 4104 (`<if_group>windows_powershell</if_group>`) on `win.eventdata.scriptBlockText`, same technique (T1490) and level 14. Query-only WMI (`Get-WmiObject Win32_ShadowCopy` with no `Remove-*` or `Delete()`) still does not match. Backup `vssadmin list shadows` in TC-07 is unchanged.

Regression test path: `tests/sample_events/TC-01/v3_powershell_wmi.json` and `test_tc01_v3_powershell_wmi_missed_by_legacy_regex` in `tests/test_rules.py`. That test compiles the original command-line regex, asserts every v3 sample misses it, and asserts the current ruleset returns 100101 on Sysmon EID 1 and 100122 on 4104.
