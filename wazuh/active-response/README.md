# Host isolation active response

Firewall-based containment for the two level-15 rules: `100102` (ransom note / encryption artifact) and `100121` (mass file-write burst). The action runs on the alerting Windows agent (`<location>local</location>`). There is no timeout. Rollback is manual.

## Install paths (Windows agent)

Copy both files into the agent active-response bin directory:

```
C:\Program Files (x86)\ossec-agent\active-response\bin\isolate-host.cmd
C:\Program Files (x86)\ossec-agent\active-response\bin\isolate-host.ps1
```

On the manager, merge `ar-config.snippet.xml` into `/var/ossec/etc/ossec.conf` (keep a single `<ossec_config>` root). Replace `192.0.2.10` and `192.0.2.0/24` in `<extra_args>` with the lab manager IPv4 and the management CIDR that is allowed to RDP (3389) and WinRM (5985). Restart:

```
sudo systemctl restart wazuh-manager
```

## What it does

Creates the named firewall group `RansomwareIsolation`. Existing enabled rules are disabled and every profile default becomes Block/Block, except:

- Wazuh manager IP, TCP 1514 (events) and 1515 (enrollment), inbound and outbound
- Management CIDR, inbound TCP 3389 and 5985

Writes `C:\ProgramData\ossec-agent\isolation.json` with UTC timestamp and triggering rule id. Logs to `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log`.

## Test with agent_control -b

List the registered command (expect `isolate-host0` because `timeout_allowed` is no), then fire it at one lab agent IP:

```
/var/ossec/bin/agent_control -L
/var/ossec/bin/agent_control -b AGENT_IP -f isolate-host0
```

Confirm the marker file and the `RansomwareIsolation` group on the agent. Do this on a VM with console access.

## Rollback one-liner

Elevated on the isolated host:

```
powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files (x86)\ossec-agent\active-response\bin\isolate-host.ps1" -Rollback
```

That removes the group, restores the snapshotted profile defaults and re-enables the rules recorded in the marker, then deletes `isolation.json`.

## Blast-radius warning

Isolation cuts DNS, DHCP renewals, SMB, AD, HTTP, and every other path except the manager ports and RDP/WinRM from the management CIDR. A wrong `ManagerIp` or `MgmtCidr` can strand the host with no remote recovery except the hypervisor console. Do not enable this on the only jump box. Re-running isolate while a marker exists is a no-op so a second level-15 alert does not wipe the rollback snapshot.
