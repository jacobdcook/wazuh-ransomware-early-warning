#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Isolate this Windows host with a named firewall group, or roll the isolation back.

.PARAMETER ManagerIp
    Wazuh manager IPv4. Outbound (and inbound) TCP 1514/1515 stay allowed to this address.

.PARAMETER MgmtCidr
    Management subnet in CIDR form. Inbound TCP 3389/5985 stay allowed from this range.

.PARAMETER RuleId
    Triggering Wazuh rule id written into the marker file (from the AR JSON).

.PARAMETER Rollback
    Remove the RansomwareIsolation group, restore prior firewall state, delete the marker.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ManagerIp = '',
    [string]$MgmtCidr = '',
    [string]$RuleId = 'unknown',
    [switch]$Rollback
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$GroupName = 'RansomwareIsolation'
$MarkerPath = 'C:\ProgramData\ossec-agent\isolation.json'
$AgentRoot = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
if (-not (Test-Path -LiteralPath $AgentRoot)) {
    $AgentRoot = 'C:\Program Files (x86)\ossec-agent'
}
$ArLogPath = Join-Path $AgentRoot 'active-response\active-responses.log'

function Write-ArLog {
    param([string]$Message)
    $line = '{0} isolate-host: {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $line
    try {
        $dir = Split-Path -Parent $script:ArLogPath
        if (Test-Path -LiteralPath $dir) {
            Add-Content -LiteralPath $script:ArLogPath -Value $line
        }
    } catch {
        Write-Host ('{0} isolate-host: log write failed: {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $_.Exception.Message)
    }
}

function Test-Ipv4 {
    param([string]$Value)
    return $Value -match '^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$'
}

function Test-Cidr {
    param([string]$Value)
    return $Value -match '^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)/(3[0-2]|[12]?\d)$'
}

function Get-IsolationRules {
    Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.Group -eq $GroupName }
}

function Remove-IsolationGroup {
    $existing = @(Get-IsolationRules)
    if ($existing.Count -eq 0) { return }
    if ($PSCmdlet.ShouldProcess($GroupName, 'Remove firewall rule group')) {
        $existing | Remove-NetFirewallRule
    }
}

function Restore-FirewallState {
    param($Marker)
    if ($null -ne $Marker.profiles) {
        foreach ($p in @($Marker.profiles)) {
            $name = [string]$p.name
            $inAction = [string]$p.DefaultInboundAction
            $outAction = [string]$p.DefaultOutboundAction
            if (-not $name) { continue }
            if ($PSCmdlet.ShouldProcess($name, "Restore profile inbound=$inAction outbound=$outAction")) {
                Set-NetFirewallProfile -Profile $name -DefaultInboundAction $inAction -DefaultOutboundAction $outAction
            }
        }
    } else {
        if ($PSCmdlet.ShouldProcess('Domain,Public,Private', 'Restore default inbound Block / outbound Allow')) {
            Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
        }
    }
    foreach ($id in @($Marker.disabled_instance_ids)) {
        $sid = [string]$id
        if (-not $sid) { continue }
        $rule = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.InstanceID -eq $sid }
        if ($null -eq $rule) { continue }
        if ($PSCmdlet.ShouldProcess($sid, 'Re-enable firewall rule')) {
            Enable-NetFirewallRule -InputObject $rule
        }
    }
}

function Invoke-Rollback {
    Write-ArLog 'rollback start'
    $marker = $null
    if (Test-Path -LiteralPath $MarkerPath) {
        try {
            $marker = Get-Content -LiteralPath $MarkerPath -Raw | ConvertFrom-Json
        } catch {
            Write-ArLog ("marker parse failed, continuing: {0}" -f $_.Exception.Message)
        }
    }
    Remove-IsolationGroup
    if ($null -ne $marker) {
        Restore-FirewallState -Marker $marker
    } else {
        if ($PSCmdlet.ShouldProcess('Domain,Public,Private', 'Restore default inbound Block / outbound Allow')) {
            Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
        }
    }
    if (Test-Path -LiteralPath $MarkerPath) {
        if ($PSCmdlet.ShouldProcess($MarkerPath, 'Remove isolation marker')) {
            Remove-Item -LiteralPath $MarkerPath -Force
        }
    }
    Write-ArLog 'rollback complete'
}

function New-AllowRule {
    param(
        [string]$Name,
        [string]$Direction,
        [string]$RemoteAddress,
        [string[]]$RemotePort,
        [string[]]$LocalPort
    )
    $common = @{
        Name          = $Name
        DisplayName   = $Name
        Group         = $GroupName
        Direction     = $Direction
        Action        = 'Allow'
        Protocol      = 'TCP'
        RemoteAddress = $RemoteAddress
        Enabled       = 'True'
        Profile       = 'Any'
        ErrorAction   = 'Stop'
    }
    if ($RemotePort) { $common['RemotePort'] = $RemotePort }
    if ($LocalPort) { $common['LocalPort'] = $LocalPort }
    if ($PSCmdlet.ShouldProcess($Name, 'Create allow rule')) {
        New-NetFirewallRule @common | Out-Null
    }
}

function Invoke-Isolate {
    if (-not (Test-Ipv4 -Value $ManagerIp)) {
        throw "ManagerIp must be an IPv4 address (got '$ManagerIp'). Set extra_args on the manager command."
    }
    if (-not (Test-Cidr -Value $MgmtCidr)) {
        throw "MgmtCidr must be IPv4 CIDR (got '$MgmtCidr'). Set extra_args on the manager command."
    }

    if (Test-Path -LiteralPath $MarkerPath) {
        Write-ArLog ("already isolated; marker present (rule_id={0})" -f $RuleId)
        return
    }

    Write-ArLog ("isolate start rule_id={0} manager={1} mgmt={2}" -f $RuleId, $ManagerIp, $MgmtCidr)

    $profiles = @(Get-NetFirewallProfile | ForEach-Object {
            [pscustomobject]@{
                name                  = [string]$_.Name
                DefaultInboundAction  = [string]$_.DefaultInboundAction
                DefaultOutboundAction = [string]$_.DefaultOutboundAction
            }
        })

    $toDisable = @(
        Get-NetFirewallRule -ErrorAction SilentlyContinue |
            Where-Object { $_.Enabled -eq 'True' -and $_.Group -ne $GroupName }
    )
    $disabledIds = @($toDisable | ForEach-Object { [string]$_.InstanceID })

    Remove-IsolationGroup
    New-AllowRule -Name 'RansomwareIsolation-Allow-Manager-Out' -Direction Outbound -RemoteAddress $ManagerIp -RemotePort @('1514', '1515')
    New-AllowRule -Name 'RansomwareIsolation-Allow-Manager-In' -Direction Inbound -RemoteAddress $ManagerIp -LocalPort @('1514', '1515')
    New-AllowRule -Name 'RansomwareIsolation-Allow-Mgmt-In' -Direction Inbound -RemoteAddress $MgmtCidr -LocalPort @('3389', '5985')

    if ($toDisable.Count -gt 0 -and $PSCmdlet.ShouldProcess("$($toDisable.Count) rules", 'Disable existing enabled firewall rules')) {
        $toDisable | Disable-NetFirewallRule
    }
    if ($PSCmdlet.ShouldProcess('Domain,Public,Private', 'Default inbound/outbound Block')) {
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
    }

    $markerDir = Split-Path -Parent $MarkerPath
    $payload = [pscustomobject]@{
        timestamp             = [datetime]::UtcNow.ToString('o')
        rule_id               = $RuleId
        manager_ip            = $ManagerIp
        mgmt_cidr             = $MgmtCidr
        disabled_instance_ids = $disabledIds
        profiles              = $profiles
    }
    if ($PSCmdlet.ShouldProcess($MarkerPath, 'Write isolation marker')) {
        if (-not (Test-Path -LiteralPath $markerDir)) {
            New-Item -ItemType Directory -Path $markerDir -Force | Out-Null
        }
        $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $MarkerPath -Encoding UTF8
    }

    Write-ArLog ("isolate complete rule_id={0} marker={1}" -f $RuleId, $MarkerPath)
}

try {
    if ($Rollback) {
        Invoke-Rollback
    } else {
        Invoke-Isolate
    }
} catch {
    Write-ArLog ("failed: {0}" -f $_.Exception.Message)
    throw
}
