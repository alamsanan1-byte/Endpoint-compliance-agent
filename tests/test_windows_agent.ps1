# Self-contained behaviour tests: no Pester download and no changes to the host configuration.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../agents/windows/check.ps1"
$script:assertions = 0
function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "Assertion failed: $Message" }
    $script:assertions++
}
$script:bitlocker = [pscustomobject]@{ProtectionStatus='On'; EncryptionPercentage=100}
function Get-BitLockerVolume { [CmdletBinding()]param($MountPoint); return $script:bitlocker }
Assert-True (Get-DiskEncryptionFact).enabled 'Fully encrypted and protected system drive'
$script:bitlocker.ProtectionStatus = 'Off'
Assert-True (-not (Get-DiskEncryptionFact).enabled) 'Suspended BitLocker must not pass'
$script:bitlocker.ProtectionStatus = 'On'; $script:bitlocker.EncryptionPercentage = 50
Assert-True (-not (Get-DiskEncryptionFact).enabled) 'Partial encryption must not pass'
$script:bitlocker.EncryptionPercentage = 100
function Get-HotFix { [CmdletBinding()]param(); [pscustomobject]@{InstalledOn=(Get-Date).AddDays(-5)} }
Assert-True ((Get-PatchLevelFact).days_since_update -ge 5) 'Hotfix age collected'
$script:profiles = @([pscustomobject]@{Enabled=$true},[pscustomobject]@{Enabled=$true},[pscustomobject]@{Enabled=$true})
function Get-NetFirewallProfile { [CmdletBinding()]param(); return $script:profiles }
Assert-True (Get-FirewallFact).enabled 'All three firewall profiles enabled'
$script:profiles[1].Enabled = $false
Assert-True (-not (Get-FirewallFact).enabled) 'A disabled profile must be detected'
$script:profiles[1].Enabled = $true
function Get-MpComputerStatus {
    [CmdletBinding()]param()
    [pscustomobject]@{AntivirusEnabled=$true; AMServiceEnabled=$true; RealTimeProtectionEnabled=$true;
        AntivirusSignatureLastUpdated=(Get-Date).AddDays(-1)}
}
Assert-True (Get-AntivirusFact).enabled 'Defender running'
function Get-LocalGroupMember {
    [CmdletBinding()]param($SID)
    if ($SID -ne 'S-1-5-32-544') { throw 'Use language-independent Administrators SID' }
    @([pscustomobject]@{Name="$env:COMPUTERNAME\Administrator"}, [pscustomobject]@{Name='EXAMPLE\Domain Admins'})
}
$admins = (Get-LocalAdminsFact).members
Assert-True ($admins -contains 'Administrator') 'Local hostname prefix removed'
Assert-True ($admins -contains 'EXAMPLE\Domain Admins') 'Domain-qualified identity preserved'
function Get-ItemProperty {
    [CmdletBinding()]param($LiteralPath)
    if ($LiteralPath -like '*Policies\System') { return [pscustomobject]@{InactivityTimeoutSecs=300} }
    if ($LiteralPath -like '*Session Manager') { return [pscustomobject]@{} }
    if ($LiteralPath -like '*\SyntheticApp') { return [pscustomobject]@{DisplayName='Synthetic Editor'} }
    throw "Unexpected registry read in test"
}
function Test-Path { [CmdletBinding()]param($LiteralPath); return ($LiteralPath -like '*Uninstall') }
function Get-ChildItem { [CmdletBinding()]param($LiteralPath); [pscustomobject]@{PSPath="$LiteralPath\SyntheticApp"} }
Assert-True ((Get-ScreenLockFact).timeout_minutes -eq 5) 'Machine lock policy converted to minutes'
Assert-True (-not (Get-PendingRebootFact).required) 'Absent reboot flags'
Assert-True ((Get-SoftwareFact).installed -contains 'Synthetic Editor') 'Installed software inventory'
$report = New-EndpointReport -Id 'TEST-WINDOWS'
Assert-True ($report.checks.Count -eq 8) 'Eight controls emitted'
Assert-True (@($report.checks | Where-Object status -eq 'error').Count -eq 0) 'All synthetic probes succeed'
# Test command failure separately from a policy failure.
function Get-BitLockerVolume { [CmdletBinding()]param($MountPoint); throw 'Synthetic permission denied' }
$failed = New-EndpointReport -Id 'TEST-WINDOWS-ERROR'
$disk = $failed.checks | Where-Object id -eq 'disk_encryption'
Assert-True ($disk.status -eq 'error' -and $null -eq $disk.value) 'Permission errors never become false compliance'
$encoded = $report | ConvertTo-Json -Depth 8
$decoded = $encoded | ConvertFrom-Json
Assert-True ($decoded.checks.Count -eq 8) 'JSON round trip'
# Store only synthetic reports for the shared Python schema validator.
$directory = [IO.Path]::Combine($PSScriptRoot, '..', 'output')
[IO.Directory]::CreateDirectory($directory) | Out-Null
[IO.File]::WriteAllText([IO.Path]::Combine($directory, 'windows-test.json'), $encoded, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText([IO.Path]::Combine($directory, 'windows-error-test.json'), ($failed | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
Write-Output "$script:assertions Windows agent assertions passed. Synthetic reports exported."
