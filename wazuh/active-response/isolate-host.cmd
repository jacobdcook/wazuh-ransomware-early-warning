@echo off
setlocal
REM Windows active-response launcher for isolate-host.ps1.
REM Wazuh 4.x writes one JSON payload to stdin. This wrapper extracts
REM parameters.alert.rule.id (and extra_args), then invokes the sibling
REM script with -ExecutionPolicy Bypass.
set "PS1=%~dp0isolate-host.ps1"
if not exist "%PS1%" (
    echo isolate-host.ps1 not found next to isolate-host.cmd 1>&2
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ps1Path = $env:PS1;" ^
  "$raw = [Console]::In.ReadToEnd();" ^
  "$invoke = New-Object System.Collections.Generic.List[string];" ^
  "if (-not [string]::IsNullOrWhiteSpace($raw)) {" ^
  "  $j = ConvertFrom-Json -InputObject $raw;" ^
  "  if ([string]$j.command -eq 'delete') { $invoke.Add('-Rollback') }" ^
  "  else {" ^
  "    $ruleId = [string]$j.parameters.alert.rule.id;" ^
  "    if ($ruleId) { $invoke.Add('-RuleId'); $invoke.Add($ruleId) }" ^
  "    foreach ($x in @($j.parameters.extra_args)) { if ($null -ne $x -and [string]$x -ne '') { $invoke.Add([string]$x) } }" ^
  "  }" ^
  "}" ^
  "& $ps1Path @($invoke.ToArray());" ^
  "if (-not $?) { exit 1 }; exit 0"

exit /b %ERRORLEVEL%
