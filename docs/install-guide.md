# Install guide

Single-node Wazuh 4.x lab procedure. None of these steps are claimed as already run against a live manager.

## Manager sizing

## All-in-one manager install

## Ports

## Custom rules

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

Do not add eventchannel blocks until enrollment succeeds. That paste and restart live in a later section. Manager must accept 1515/tcp from the endpoint for registration and 1514/tcp for events.

## Eventchannel snippet

## Sysmon deploy

## Active response install

## Smoke test
