#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$RepositoryPath,
    [Parameter(Mandatory=$true)][string]$CollectorUrl,
    [Parameter(Mandatory=$true)][string]$ApiKeyFile
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath $RepositoryPath).Path
$keyPath = (Resolve-Path -LiteralPath $ApiKeyFile).Path
$scriptPath = Join-Path $repo 'agents\windows\run-scheduled.ps1'
if (-not (Test-Path -LiteralPath $scriptPath)) { throw 'Agent runner is missing' }
foreach ($argument in @($scriptPath, $CollectorUrl, $keyPath)) {
    if ($argument.Contains('"') -or $argument.Contains("`n")) { throw 'Invalid argument quoting' }
}
# API key stays in a SYSTEM/Administrators-readable file, never a task argument.
$arguments = '-NoProfile -NonInteractive -File "{0}" -CollectorUrl "{1}" -ApiKeyFile "{2}"' -f $scriptPath, $CollectorUrl, $keyPath
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'Endpoint Compliance Agent' -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Description 'Hourly read-only compliance collection'
