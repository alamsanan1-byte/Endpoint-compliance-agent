#requires -Version 5.1
<# Read-only Windows endpoint inventory. Policy is evaluated by the collector. #>
[CmdletBinding()]
param(
    [string]$DeviceId = $env:DEVICE_ID,
    [string]$Server = $env:COLLECTOR_URL,
    [string]$OutputPath,
    [switch]$Send
)

function Get-DiskEncryptionFact {
    $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    if ($null -eq $volume) { throw 'No operating-system volume returned' }
    return @{ enabled = ([string]$volume.ProtectionStatus -eq 'On' -and
        [int]$volume.EncryptionPercentage -eq 100) }
}

function Get-PatchLevelFact {
    $last = Get-HotFix -ErrorAction Stop | Where-Object { $null -ne $_.InstalledOn } |
        Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($null -eq $last) { throw 'No installed hotfix date available' }
    $age = ((Get-Date).ToUniversalTime() - $last.InstalledOn.ToUniversalTime()).TotalDays
    if ($age -lt -0.01) { throw 'Hotfix time is in the future; check the system clock' }
    return @{ days_since_update = [math]::Round([math]::Max(0, $age), 2) }
}

function Get-FirewallFact {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    if ($profiles.Count -ne 3) { throw 'Expected Domain, Private and Public firewall profiles' }
    return @{ enabled = (@($profiles | Where-Object { -not $_.Enabled }).Count -eq 0) }
}

function Get-AntivirusFact {
    $status = Get-MpComputerStatus -ErrorAction Stop
    if ($null -eq $status -or $null -eq $status.AntivirusSignatureLastUpdated) {
        throw 'Defender signature timestamp unavailable'
    }
    $age = ((Get-Date).ToUniversalTime() -
        $status.AntivirusSignatureLastUpdated.ToUniversalTime()).TotalDays
    if ($age -lt -0.01) { throw 'Defender signature timestamp is in the future' }
    return @{
        enabled = [bool]($status.AntivirusEnabled -and $status.AMServiceEnabled -and
            $status.RealTimeProtectionEnabled)
        definition_age_days = [math]::Round([math]::Max(0, $age), 2)
    }
}

function Get-LocalAdminsFact {
    $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object {
        $name = [string]$_.Name
        $prefix = "$env:COMPUTERNAME\"
        if ($name.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            $name.Substring($prefix.Length)
        } else { $name }
    } | Sort-Object -Unique)
    return @{ members = @($members) }
}

function Get-ScreenLockFact {
    # Machine-wide inactivity policy; never mistake the SYSTEM account's HKCU for a user's.
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $settings = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
    $seconds = 0
    if ($null -ne $settings.PSObject.Properties['InactivityTimeoutSecs']) {
        $seconds = [int]$settings.InactivityTimeoutSecs
    }
    return @{ enabled = ($seconds -gt 0); timeout_minutes = $seconds / 60.0 }
}

function Get-PendingRebootFact {
    $cbs = Test-Path -LiteralPath (
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    ) -ErrorAction Stop
    $wu = Test-Path -LiteralPath (
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    ) -ErrorAction Stop
    $session = Get-ItemProperty -LiteralPath (
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    ) -ErrorAction Stop
    $pending = $session.PSObject.Properties['PendingFileRenameOperations']
    return @{ required = [bool]($cbs -or $wu -or ($null -ne $pending -and $pending.Value)) }
}

function Get-SoftwareFact {
    # Registry reads avoid Win32_Product, which can trigger MSI repair actions.
    $names = @(
        foreach ($path in @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        )) {
            if (Test-Path -LiteralPath $path -ErrorAction Stop) {
                Get-ChildItem -LiteralPath $path -ErrorAction Stop | ForEach-Object {
                    $app = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
                    if ($app.DisplayName) { [string]$app.DisplayName }
                }
            }
        }
    ) | Sort-Object -Unique
    return @{ installed = @($names) }
}

function New-EndpointReport {
    param([string]$Id)
    if (-not $Id) {
        $machine = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' `
            -ErrorAction Stop).MachineGuid
        if (-not $machine) { throw 'MachineGuid unavailable; provide -DeviceId' }
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($machine))
            $Id = 'windows-' + (-join ($hash | ForEach-Object { $_.ToString('x2') })).Substring(0,24)
        } finally { $sha.Dispose() }
    }
    if ($Id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') { throw 'Invalid device ID' }
    $functions = [ordered]@{
        disk_encryption = 'Get-DiskEncryptionFact'
        patch_level = 'Get-PatchLevelFact'
        firewall = 'Get-FirewallFact'
        antivirus = 'Get-AntivirusFact'
        local_admins = 'Get-LocalAdminsFact'
        screen_lock = 'Get-ScreenLockFact'
        pending_reboot = 'Get-PendingRebootFact'
        unauthorised_software = 'Get-SoftwareFact'
    }
    $checks = @(foreach ($entry in $functions.GetEnumerator()) {
        try {
            $value = & $entry.Value
            @{ id = $entry.Key; status = 'pass'; value = $value; detail = $null }
        } catch {
            $detail = [string]$_.Exception.Message
            if ($detail.Length -gt 1000) { $detail = $detail.Substring(0,1000) }
            @{ id = $entry.Key; status = 'error'; value = $null; detail = $detail }
        }
    })
    return @{
        device_id = $Id; hostname = [Environment]::MachineName; os = 'windows'
        os_version = [Environment]::OSVersion.Version.ToString()
        collected_at = [DateTime]::UtcNow.ToString('o'); agent_version = '1.0.0'; checks = $checks
    }
}

function Send-EndpointReport {
    param([string]$Json, [string]$Collector)
    $uri = [Uri]$Collector
    $localHttp = $uri.Scheme -eq 'http' -and $uri.Host -in @('localhost','127.0.0.1','[::1]')
    if ((-not $localHttp -and $uri.Scheme -ne 'https') -or $uri.UserInfo -or
        $uri.Query -or $uri.Fragment -or -not $uri.Host) {
        throw 'Collector requires HTTPS (HTTP allowed only for loopback)'
    }
    if (-not $env:API_KEY) { throw 'Set API_KEY before submitting' }
    Add-Type -AssemblyName System.Net.Http
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(20)
    try {
        $client.DefaultRequestHeaders.Authorization =
            [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $env:API_KEY)
        $body = [System.Net.Http.StringContent]::new($Json, [Text.Encoding]::UTF8, 'application/json')
        try {
            $response = $client.PostAsync($Collector.TrimEnd('/') + '/reports', $body).GetAwaiter().GetResult()
            try { $null = $response.EnsureSuccessStatusCode() } finally { $response.Dispose() }
        } finally { $body.Dispose() }
    } finally { $client.Dispose() }
}

if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    try {
        if (-not $Server) { $Server = 'http://127.0.0.1:8000' }
        $json = New-EndpointReport -Id $DeviceId | ConvertTo-Json -Depth 8
        if ($OutputPath) { [IO.File]::WriteAllText($OutputPath, $json, [Text.UTF8Encoding]::new($false)) }
        Write-Output $json
        if ($Send) {
            try { Send-EndpointReport -Json $json -Collector $Server }
            catch { throw 'Submission failed. Check connectivity, TLS and credentials; local report retained.' }
        }
    } catch { Write-Error $_; exit 1 }
}
