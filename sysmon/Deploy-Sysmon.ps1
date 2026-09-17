#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install Sysmon or apply the lab baseline config. Idempotent.

.PARAMETER SysmonExe
    Path to Sysmon.exe or Sysmon64.exe.

.PARAMETER ConfigPath
    Path to sysmonconfig.xml.

.PARAMETER Verify
    Confirm the service is Running, print the config SHA256, and check the Operational log.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string]$SysmonExe = (Join-Path $PSScriptRoot 'Sysmon64.exe'),

    [Parameter()]
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'sysmonconfig.xml'),

    [Parameter()]
    [switch]$Verify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-SysmonService {
    Get-Service -Name @('Sysmon64', 'Sysmon') -ErrorAction SilentlyContinue |
        Select-Object -First 1
}

function Resolve-ExistingPath {
    param([string]$Path, [string]$Label)
    $full = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if (-not (Test-Path -LiteralPath $full)) {
        throw "$Label not found: $full"
    }
    return $full
}

function Resolve-SysmonBinary {
    param([string]$Preferred, [bool]$MustExist)
    $candidates = @($Preferred)
    if ($env:SystemRoot) {
        $candidates += @(
            (Join-Path $env:SystemRoot 'Sysmon64.exe'),
            (Join-Path $env:SystemRoot 'Sysmon.exe')
        )
    }
    foreach ($c in $candidates) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        $full = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($c)
        if (Test-Path -LiteralPath $full) { return $full }
    }
    if ($MustExist) {
        throw "SysmonExe not found: $Preferred"
    }
    return $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Preferred)
}

function Invoke-Sysmon {
    param(
        [string]$Exe,
        [string[]]$Arguments,
        [string]$Action
    )
    if ($PSCmdlet.ShouldProcess($Exe, $Action)) {
        & $Exe @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Sysmon $Action failed with exit code $LASTEXITCODE"
        }
    }
}

$ConfigPath = Resolve-ExistingPath -Path $ConfigPath -Label 'ConfigPath'
$service = Get-SysmonService

if ($null -eq $service) {
    $SysmonExe = Resolve-SysmonBinary -Preferred $SysmonExe -MustExist $true
    Invoke-Sysmon -Exe $SysmonExe -Arguments @('-accepteula', '-i', $ConfigPath) -Action 'Install (-accepteula -i)'
} else {
    $SysmonExe = Resolve-SysmonBinary -Preferred $SysmonExe -MustExist $false
    if (-not (Test-Path -LiteralPath $SysmonExe)) {
        throw "Sysmon service exists but SysmonExe not found: $SysmonExe"
    }
    Invoke-Sysmon -Exe $SysmonExe -Arguments @('-c', $ConfigPath) -Action 'Apply config (-c)'
}

$service = Get-SysmonService
if ($null -eq $service) {
    if ($WhatIfPreference) {
        Write-Host "WhatIf: Sysmon would be installed from $SysmonExe with $ConfigPath"
        $hash = (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash
        Write-Host "Loaded config SHA256: $hash"
        return
    }
    throw 'Sysmon service not found after install or config apply'
}
if ($service.Status -ne 'Running') {
    if ($PSCmdlet.ShouldProcess($service.Name, 'Start service')) {
        Start-Service -Name $service.Name
        $service.Refresh()
    }
}
if ($service.Status -ne 'Running') {
    throw "Sysmon service $($service.Name) is $($service.Status)"
}

Write-Host "Sysmon service $($service.Name) is Running"

$hash = (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash
Write-Host "Loaded config SHA256: $hash"

if ($Verify) {
    $log = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
    Write-Host "Operational log present; records=$($log.RecordCount)"
}
