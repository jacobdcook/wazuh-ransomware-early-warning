# Install guide

Single-node Wazuh 4.x lab procedure for Riverbend Managed IT Services. None of these steps are claimed as already run against a live manager. Offline checks that did run in this checkout are in [../VERIFICATION.md](../VERIFICATION.md). Sizing and ports match the lab facts in this pack: Ubuntu 22.04, 8 vCPU / 16 GB RAM / 500 GB disk, Wazuh 4.x all-in-one.

Work the manager first, then each Windows endpoint (`WS-FIN-02`, `WS-OPS-07`, `SRV-FILE-01`, `SRV-DC-01`). Replace `MANAGER_IP` with the Ubuntu manager IPv4. Domain `RIVERBEND` and those hostnames are fictitious.

## Manager sizing

| Item | Lab value |
|---|---|
| Role | Single node (indexer + manager + dashboard on one host) |
| OS | Ubuntu 22.04 |
| CPU / RAM / disk | 8 vCPU / 16 GB RAM / 500 GB |
| Wazuh | 4.x all-in-one |
| Sysmon on endpoints | 15.x with [../sysmon/sysmonconfig.xml](../sysmon/sysmonconfig.xml) |

500 GB is the lab disk, not a production retention SLA. Do not put live archives in git.

Alert routing once the pack is loaded: level 12 and above is immediate notification; level 10–11 (`100110`, `100111`) is the daily triage queue. Active response is bound only to level 15 (`100102`, `100121`), local to the agent, with an allowlist for the manager IP and the management subnet. See [coverage-map.md](coverage-map.md).

## All-in-one manager install

On a fresh Ubuntu 22.04 host that meets the table above, use the Wazuh 4.x all-in-one installer (`-a`). This is the command pattern, not a record of a completed install:

```
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

The script prints dashboard credentials and writes them under `wazuh-install-files.tar`. Keep that archive off git. If the host already has a Wazuh 4.x all-in-one from an earlier lab snapshot, skip the installer and continue at Ports.

Confirm the manager unit after install:

```
sudo systemctl is-active wazuh-manager
sudo systemctl is-active wazuh-indexer
sudo systemctl is-active wazuh-dashboard
```

Clone or copy this repository onto the manager so the `cp` paths in later sections resolve. Parent stock rule IDs (`61603`, `61612`, `61613`, `61615`, `60100`, `60001`, group `windows_powershell`) must be confirmed with `wazuh-logtest` on the version that actually landed. They drift between 4.x releases.

## Ports

Open these on the manager, inbound from lab Windows agents and from the analyst station. Dashboard may be 1443 or 443 depending on the 4.x installer; try both if the browser cannot connect.

| Port | Direction | Use |
|---|---|---|
| 1514/tcp | agents → manager | Agent events |
| 1515/tcp | agents → manager | Enrollment (`agent-auth` / MSI register) |
| 1443/tcp or 443/tcp | analyst → manager | Dashboard |
| 55000/tcp | analyst / API clients → manager | Wazuh API |

Example with `ufw` (procedure only):

```
sudo ufw allow 1514/tcp
sudo ufw allow 1515/tcp
sudo ufw allow 1443/tcp
sudo ufw allow 443/tcp
sudo ufw allow 55000/tcp
sudo ufw status
```

Do not expose 1514/1515/55000 to the public internet. Lab agents only.

## Custom rules

Copy [../wazuh/rules/local_rules.xml](../wazuh/rules/local_rules.xml) over the stock custom rules path, then restart the manager. This file is the twelve primary rules `100100`–`100111` plus support `100120`–`100122`.

```
sudo cp wazuh/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

`xmllint --noout wazuh/rules/local_rules.xml` must be clean before the copy. After restart, the smoke test section is the check that the file loaded.

## Agent enrollment

Use one of the two methods below. Enrollment is 1515/tcp. After the agent is active, events flow on 1514/tcp. Lab agent names: `WS-FIN-02`, `WS-OPS-07`, `SRV-FILE-01`, `SRV-DC-01`. Replace `MANAGER_IP` with the Ubuntu manager address.

### MSI with `WAZUH_MANAGER`

On the Windows endpoint, install the Wazuh 4.x agent MSI with the manager address as a property:

```
msiexec.exe /i wazuh-agent-4.x.x-x.msi /q WAZUH_MANAGER="MANAGER_IP" WAZUH_AGENT_NAME="WS-FIN-02"
```

The installer registers the agent during setup. Confirm the host shows as active on the manager before collecting logs.

### `agent-auth`

If the MSI was installed without `WAZUH_MANAGER`, register from an elevated prompt:

```
cd "C:\Program Files (x86)\ossec-agent"
.\agent-auth.exe -m MANAGER_IP -A WS-FIN-02
Restart-Service -Name wazuh
```

`-A` sets the agent name the manager will display. Re-run is safe if the key already exists; the agent keeps the existing key.

Do not add eventchannel blocks until enrollment succeeds. That paste and restart live in the next section. Manager must accept 1515/tcp from the endpoint for registration and 1514/tcp for events.

## Eventchannel snippet

Paste the four `<localfile>` blocks from [../wazuh/agent/ossec.conf.snippet.xml](../wazuh/agent/ossec.conf.snippet.xml) into the Windows agent's `C:\Program Files (x86)\ossec-agent\ossec.conf`, inside the existing `<ossec_config>` element. Do not nest a second `<ossec_config>`. The repo file wraps those blocks in a root so `xmllint` can parse it; only the inner `<localfile>` elements belong in the live agent file.

Channels:

- `Microsoft-Windows-Sysmon/Operational`
- `Microsoft-Windows-PowerShell/Operational`
- `Security` (query keeps 4624, 4625, 4648, 4688, 4698, 4720, 4732, 5140, 5145, 1102 and drops 4634, 4658, 4663, 5156, 5158)
- `System`

Then:

```
Restart-Service -Name wazuh
```

Confirm the agent stays Active on the manager. Sysmon events will not appear until the next section has run at least once.

## Sysmon deploy

On each Windows endpoint, install Sysmon 15.x (64-bit) from Microsoft Sysinternals, then apply this repo's baseline. The binary is not in git. From an elevated prompt in the `sysmon/` directory of a checkout on the guest:

```
.\Deploy-Sysmon.ps1 -SysmonExe .\Sysmon64.exe -ConfigPath .\sysmonconfig.xml -Verify
```

If the service is absent, the script runs `Sysmon64.exe -accepteula -i` with the config. If it is already installed, it applies `-c`. `-Verify` checks the service is Running and prints the loaded config SHA256.

Spot-check the Operational log:

```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5
```

Expect EID 1, 3, 7, 10, 11, 12, 13, 22 per [../sysmon/README.md](../sysmon/README.md). Windows Update, Defender, and Sysmon itself are excluded in the config.

## Active response install

Isolation is local Windows firewall, bound only to level 15 rules `100102` and `100121`. There is no timeout. Rollback is manual. Full notes: [../wazuh/active-response/README.md](../wazuh/active-response/README.md).

On the Windows agent, copy both launchers into the agent bin directory:

```
C:\Program Files (x86)\ossec-agent\active-response\bin\isolate-host.cmd
C:\Program Files (x86)\ossec-agent\active-response\bin\isolate-host.ps1
```

Sources: [../wazuh/active-response/isolate-host.cmd](../wazuh/active-response/isolate-host.cmd) and [../wazuh/active-response/isolate-host.ps1](../wazuh/active-response/isolate-host.ps1).

On the manager, merge [../wazuh/active-response/ar-config.snippet.xml](../wazuh/active-response/ar-config.snippet.xml) into `/var/ossec/etc/ossec.conf` inside the existing `<ossec_config>` (do not nest a second root). Replace `192.0.2.10` and `192.0.2.0/24` in `<extra_args>` with the lab manager IPv4 and the CIDR that may RDP (3389) and WinRM (5985) to an isolated host. Then:

```
sudo systemctl restart wazuh-manager
```

List the registered command (expect `isolate-host0` because `timeout_allowed` is no), then fire it at one lab agent IP only on a VM with console access:

```
/var/ossec/bin/agent_control -L
/var/ossec/bin/agent_control -b AGENT_IP -f isolate-host0
```

Rollback, elevated on the isolated host:

```
powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files (x86)\ossec-agent\active-response\bin\isolate-host.ps1" -Rollback
```

Wrong `ManagerIp` or `MgmtCidr` can strand the host with no path except the hypervisor console. Do not enable this on the only jump box.

## Smoke test

This section is the first check after rules are copied. It still requires a live manager. It is not a substitute for `pytest -q` in this repo (that harness does not need Wazuh).

On the manager:

```
sudo /var/ossec/bin/wazuh-logtest
```

Paste one decoded Windows JSON line (Sysmon EID 1, `vssadmin.exe delete shadows /all /quiet`) and end input with Ctrl-D:

```
{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon","channel":"Microsoft-Windows-Sysmon/Operational","computer":"WS-FIN-02"},"eventdata":{"image":"C:\\Windows\\System32\\vssadmin.exe","commandLine":"vssadmin.exe delete shadows /all /quiet","parentImage":"C:\\Windows\\System32\\cmd.exe","user":"RIVERBEND\\jdoe"}}}
```

Success is a Phase 3 line that names rule `100101` at level 14. If only the stock parent `61603` matches, `local_rules.xml` is not loaded or the field regex did not hit. If nothing matches, treat it as parent-SID drift: confirm `61603` still maps to Sysmon EID 1 on this Wazuh version before editing regexes. Repeat with an EID 11 `RANSOM_NOTE.txt` write if you also need to prove `100102` (level 15, AR).

A `vssadmin list shadows` line (TC-07 backup agent) must not raise `100101`. If it does, stop and follow [tuning.md](tuning.md).
