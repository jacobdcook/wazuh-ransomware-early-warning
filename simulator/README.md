# Encryption-behavior simulator

This tool exists to exercise Wazuh rules `100102` and `100121` with a Sysmon EID 11 burst, without touching real documents.

It is not an encryptor. On an empty sandbox directory it writes N small files, copies the originals to `<target>/.sim_backup/`, renames each file to `<name>.locked`, overwrites the renamed file with random bytes, and drops `RANSOM_NOTE.txt`. Sysmon FileCreate (EID 11, Wazuh parent `61613`) then sees the note name and the `.locked` suffix that `100102` keys on, and a burst of user-path writes that `100121` correlates. `--rollback` restores byte-identical originals and removes the note and `*.locked` files.

## Sandbox VM only

Run it on an isolated Windows lab VM that already has Sysmon (this repo's baseline) and the Wazuh agent. Do not point it at production data.

The script refuses:

- filesystem root `/`
- `C:\Windows` and anything under it
- the current user's home directory itself
- any path containing a `.git` component
- any directory that is not empty and was not created by a previous run of this simulator

The gitignored folder `simulator_sandbox/` at the repo root is the intended Linux pytest / dry-run target.

## How to run (Windows lab VM)

Create an empty folder under the lab user's local `Documents` folder (replace `labuser` with the account on the VM), then:

```
python encrypt_sim.py --target C:\Users\labuser\Documents\simulator_sandbox --files 50
```

Confirm Sysmon EID 11 for `RANSOM_NOTE.txt` and `*.locked`, then Wazuh alerts `100102` (level 15) and, with enough writes in 60 seconds, `100121`. Restore files:

```
python encrypt_sim.py --target C:\Users\labuser\Documents\simulator_sandbox --rollback
```

Why `Documents`: burst rule `100121` only counts writes that support rule `100120` matches, and `100120` watches `\Users\<name>\(Desktop|Documents|Downloads|Pictures)\`. The Sysmon FileCreate include list also only logs those folders plus ransom-note names and encrypted suffixes. A folder such as `C:\lab\...` produces the note and `.locked` events for `100102` but no countable writes, so `100121` can never fire from it. Do not use a OneDrive-redirected `Documents` (`C:\Users\<name>\OneDrive\Documents\`); `100120` does not match it. The rule was left unchanged on purpose: it scopes to the folders ransomware actually targets on a workstation, and widening it to a lab-only path would add a detection that exists only for the test.

`--files` defaults to 50. `--seed INT` makes the random overwrite reproducible. A second encrypt on the same sandbox is a no-op for files that are already locked, so backups stay intact.

If host isolation fired on `100102` or `100121`, roll the firewall back with `isolate-host.ps1 -Rollback` as documented in `wazuh/active-response/README.md`. That is separate from this script's file rollback.
