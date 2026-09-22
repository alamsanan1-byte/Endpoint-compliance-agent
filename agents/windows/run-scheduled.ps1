#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CollectorUrl,
    [Parameter(Mandatory=$true)][string]$ApiKeyFile
)
$ErrorActionPreference = 'Stop'
$directory = Join-Path $env:ProgramData 'EndpointCompliance'
New-Item -ItemType Directory -Path $directory -Force | Out-Null
# Restrict report files before storing device inventory.
& icacls.exe $directory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict report directory permissions' }
try {
    $env:API_KEY = (Get-Content -LiteralPath $ApiKeyFile -Raw).Trim()
    & "$PSScriptRoot/check.ps1" -Server $CollectorUrl -Send -OutputPath (Join-Path $directory 'latest.json') | Out-Null
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
} finally { Remove-Item Env:\API_KEY -ErrorAction SilentlyContinue }
