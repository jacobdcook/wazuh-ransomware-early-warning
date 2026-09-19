# Custom Wazuh rules (SEV-1)

Lab rules for LSASS memory access (100100, T1003.001), shadow copy deletion (100101, T1490), and ransom-note or encryption artifacts (100102, T1486). Support rule 100120 is a single Sysmon EID 11 write under a user document path (level 3). 100121 fires at level 15 when 100120 matches 30 times in 60 seconds on the same `win.system.computer`. 100102 and 100121 are the level-15 pair that later bind to host isolation.

## Install on the manager

Copy this file over the stock custom rules path, then restart the manager:

```
sudo cp wazuh/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

Confirm with `systemctl is-active wazuh-manager`. Parent SIDs 61612 (Sysmon EID 10), 61603 (EID 1), and 61613 (EID 11) come from the stock Sysmon ruleset. If a custom rule never fires, confirm those IDs with wazuh-logtest on the deployed Wazuh version before changing field regexes.

## Test one event with wazuh-logtest

On the manager, start the tester and paste a single decoded Windows JSON line. A Sysmon EID 1 event whose `win.eventdata.commandLine` contains `vssadmin.exe delete shadows /all /quiet` is the straightforward check for 100101:

```
sudo /var/ossec/bin/wazuh-logtest
```

End input with Ctrl-D. Success is a Phase 3 line that names rule `100101` at level 14. If only the stock parent `61603` matches, the custom file is not loaded or the field regex did not hit. Treat a missing parent SID as a decoder issue, not a regex issue.

What each rule misses is the `Misses:` comment above that rule in `local_rules.xml` and the bullets in `docs/coverage-map.md`.
