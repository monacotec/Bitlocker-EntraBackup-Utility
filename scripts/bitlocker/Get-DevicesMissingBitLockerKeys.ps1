#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.SignIns, ImportExcel

<#
.SYNOPSIS
    Finds hybrid Entra-joined devices that do not have a BitLocker recovery key uploaded to Entra ID.

.DESCRIPTION
    Connects to Microsoft Graph, retrieves all Windows devices (optionally filtered to hybrid-joined only),
    checks each device for BitLocker recovery key presence, and reports devices with no keys escrowed.

.PARAMETER TenantId
    The Entra ID tenant ID. If omitted, connects to the home tenant of the signed-in user.

.PARAMETER HybridOnly
    When specified, only checks devices whose trustType is "ServerAd" (hybrid Entra-joined).
    By default, all Windows devices are checked.

.PARAMETER EnabledOnly
    When specified, only checks devices where accountEnabled is true.
    Skips disabled/stale device objects in Entra.

.PARAMETER ExportPath
    Path to export results as XLSX. Defaults to C:\GI\BitLockerAudit_<timestamp>.xlsx.

.PARAMETER InactiveDays
    Flag devices that have not signed in within this many days as "Inactive". Default is 90.
    All devices are kept in the results regardless. Set to 0 to disable the inactive flag.

.EXAMPLE
    .\Get-DevicesMissingBitLockerKeys.ps1 -HybridOnly -EnabledOnly
    .\Get-DevicesMissingBitLockerKeys.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -ExportPath "C:\GI\report.xlsx"
    .\Get-DevicesMissingBitLockerKeys.ps1 -EnabledOnly -InactiveDays 30
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [switch]$HybridOnly,

    [Parameter()]
    [switch]$EnabledOnly,

    [Parameter()]
    [string]$ExportPath,

    [Parameter()]
    [int]$InactiveDays = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Logging setup ---
$logDir = 'C:\GI'
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$logFile = Join-Path $logDir "BitLockerAudit_$timestamp.log"
$xlsxFile = Join-Path $logDir "BitLockerAudit_$timestamp.xlsx"

# If caller supplied -ExportPath, honour it; otherwise default to C:\GI
if (-not $ExportPath) { $ExportPath = $xlsxFile }

function Write-Log {
    param([string]$Message, [string]$Color = 'White')
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $Message"
    Add-Content -Path $logFile -Value $entry
    Write-Host $Message -ForegroundColor $Color
}

Write-Log "Log file:    $logFile"
Write-Log "XLSX output: $ExportPath"
if ($InactiveDays -gt 0) {
    Write-Log "Devices inactive for more than $InactiveDays days will be flagged as Inactive."
}

# --- Connect to Graph ---
$scopes = @(
    'Device.Read.All',
    'BitLockerKey.Read.All'
)

$connectParams = @{ Scopes = $scopes; NoWelcome = $true }
if ($TenantId) { $connectParams['TenantId'] = $TenantId }

# Clear any cached Graph session so the browser prompts for account selection
try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}

Write-Log "Connecting to Microsoft Graph (select your admin account in the browser)..." -Color Cyan
Connect-MgGraph @connectParams

$context = Get-MgContext
Write-Log "Connected as $($context.Account) to tenant $($context.TenantId)" -Color Green

# --- Get Windows devices ---
Write-Log "Retrieving Windows devices from Entra ID..." -Color Cyan

$deviceFilter = "operatingSystem eq 'Windows'"
if ($EnabledOnly) {
    $deviceFilter += " and accountEnabled eq true"
    Write-Log "  Filtering to enabled devices only." -Color Yellow
}
if ($HybridOnly) {
    $deviceFilter += " and trustType eq 'ServerAd'"
    Write-Log "  Filtering to hybrid Entra-joined devices only." -Color Yellow
}

$allDevices = [System.Collections.Generic.List[object]]::new()
$uri = "https://graph.microsoft.com/v1.0/devices?`$filter=$deviceFilter&`$select=id,displayName,deviceId,operatingSystem,operatingSystemVersion,trustType,accountEnabled,approximateLastSignInDateTime&`$expand=registeredOwners(`$select=displayName,userPrincipalName)&`$top=999"

do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    foreach ($d in $response.value) { $allDevices.Add($d) }
    $uri = if ($response.ContainsKey('@odata.nextLink')) { $response.'@odata.nextLink' } else { $null }
} while ($uri)

Write-Log "  Found $($allDevices.Count) Windows device(s) total." -Color Green

# --- Tag stale devices (kept in results, flagged in output) ---
$inactiveCutoff = if ($InactiveDays -gt 0) { (Get-Date).AddDays(-$InactiveDays) } else { $null }
if ($inactiveCutoff) {
    $staleCount = ($allDevices | Where-Object {
        $_.approximateLastSignInDateTime -and
        [datetime]$_.approximateLastSignInDateTime -lt $inactiveCutoff
    }).Count
    $noSignInCount = ($allDevices | Where-Object { -not $_.approximateLastSignInDateTime }).Count
    Write-Log "  $staleCount device(s) inactive for more than $InactiveDays days (kept in results, flagged as Inactive)." -Color Yellow
    if ($noSignInCount -gt 0) {
        Write-Log "  $noSignInCount device(s) have no sign-in date recorded." -Color Yellow
    }
}

Write-Log "  Processing $($allDevices.Count) device(s)." -Color Green

if ($allDevices.Count -eq 0) {
    Write-Log "No devices found matching criteria. Exiting." -Color Yellow
    Disconnect-MgGraph | Out-Null
    return
}

# --- Get all BitLocker recovery keys (device IDs that have keys escrowed) ---
Write-Log "Retrieving BitLocker recovery key inventory..." -Color Cyan

# Track key count per device
$keyCountByDevice = @{}
$uri = "https://graph.microsoft.com/v1.0/informationProtection/bitlocker/recoveryKeys?`$select=id,deviceId,createdDateTime&`$top=999"

do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    foreach ($key in $response.value) {
        if ($key.deviceId) {
            $did = $key.deviceId.ToLower()
            if ($keyCountByDevice.ContainsKey($did)) {
                $keyCountByDevice[$did]++
            }
            else {
                $keyCountByDevice[$did] = 1
            }
        }
    }
    $uri = if ($response.ContainsKey('@odata.nextLink')) { $response.'@odata.nextLink' } else { $null }
} while ($uri)

Write-Log "  Found BitLocker keys for $($keyCountByDevice.Count) unique device(s)." -Color Green

# --- Compare: find devices without keys and build compliant list ---
Write-Log "Comparing devices against escrowed keys..." -Color Cyan

$missingDevices  = [System.Collections.Generic.List[PSCustomObject]]::new()
$compliantDevices = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($device in $allDevices) {
    $devId = $device.deviceId
    $owner = $device.registeredOwners | Select-Object -First 1
    $ownerName = if ($owner) { $owner.displayName } else { '' }
    $ownerUpn  = if ($owner) { $owner.userPrincipalName } else { '' }
    $keyCount  = if ($keyCountByDevice.ContainsKey($devId.ToLower())) { $keyCountByDevice[$devId.ToLower()] } else { 0 }

    $daysSinceSignIn = if ($device.approximateLastSignInDateTime) {
        [math]::Round(((Get-Date) - [datetime]$device.approximateLastSignInDateTime).TotalDays)
    } else { $null }

    $status = if (-not $device.approximateLastSignInDateTime) {
        'No Sign-In Data'
    } elseif ($inactiveCutoff -and [datetime]$device.approximateLastSignInDateTime -lt $inactiveCutoff) {
        'Inactive'
    } else {
        'Active'
    }

    $row = [PSCustomObject]@{
        DisplayName     = $device.displayName
        Owner           = $ownerName
        OwnerUPN        = $ownerUpn
        DeviceId        = $devId
        OSVersion       = $device.operatingSystemVersion
        TrustType       = $device.trustType
        Enabled         = $device.accountEnabled
        Status          = $status
        LastSignIn      = $device.approximateLastSignInDateTime
        DaysSinceSignIn = $daysSinceSignIn
        BitLockerKeys   = $keyCount
    }

    if ($keyCount -eq 0) {
        $missingDevices.Add($row)
    }
    else {
        $compliantDevices.Add($row)
    }
}

# --- Output results ---
# Sheet 1: Missing BitLocker Keys
if ($missingDevices.Count -gt 0) {
    Write-Log "$($missingDevices.Count) of $($allDevices.Count) device(s) are MISSING BitLocker keys:" -Color Red

    $missingDevices | Export-Excel -Path $ExportPath -WorksheetName 'Missing BitLocker Keys' `
        -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow -TableStyle 'Medium6' `
        -Title "Devices Missing BitLocker Keys" -TitleBold -TitleSize 14

    $missingDevices | Sort-Object DaysSinceSignIn | Format-Table DisplayName, Owner, TrustType, LastSignIn, DaysSinceSignIn -AutoSize
}
else {
    Write-Log "All $($allDevices.Count) device(s) have BitLocker keys escrowed." -Color Green
}

# Sheet 2: Compliant Devices
if ($compliantDevices.Count -gt 0) {
    $compliantDevices | Export-Excel -Path $ExportPath -WorksheetName 'Compliant Devices' `
        -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow -TableStyle 'Medium2' `
        -Title "Devices With BitLocker Keys" -TitleBold -TitleSize 14
}

# Sheet 3: Summary
$activeCount    = ($allDevices | Where-Object { -not $inactiveCutoff -or -not $_.approximateLastSignInDateTime -or [datetime]$_.approximateLastSignInDateTime -ge $inactiveCutoff }).Count
$inactiveCount  = $allDevices.Count - $activeCount
$activeMissing  = @($missingDevices | Where-Object { $_.Status -eq 'Active' }).Count

$summaryData = @(
    [PSCustomObject]@{ Metric = 'Total Windows Devices';                Count = $allDevices.Count }
    [PSCustomObject]@{ Metric = 'Active Devices';                       Count = $activeCount }
    [PSCustomObject]@{ Metric = 'Inactive Devices (>{0} days)' -f $InactiveDays; Count = $inactiveCount }
    [PSCustomObject]@{ Metric = 'Devices With BitLocker Key';           Count = $compliantDevices.Count }
    [PSCustomObject]@{ Metric = 'Devices Missing BitLocker Key';        Count = $missingDevices.Count }
    [PSCustomObject]@{ Metric = 'Active Devices Missing Key';           Count = $activeMissing }
    [PSCustomObject]@{ Metric = 'Compliance Rate - All (%)';            Count = if ($allDevices.Count -gt 0) { [math]::Round(($compliantDevices.Count / $allDevices.Count) * 100, 1) } else { 0 } }
    [PSCustomObject]@{ Metric = 'Compliance Rate - Active Only (%)';    Count = if ($activeCount -gt 0) { [math]::Round((($activeCount - $activeMissing) / $activeCount) * 100, 1) } else { 0 } }
    [PSCustomObject]@{ Metric = 'Report Generated';                     Count = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') }
)
$summaryData | Export-Excel -Path $ExportPath -WorksheetName 'Summary' `
    -AutoSize -BoldTopRow -TableStyle 'Medium1' `
    -Title "BitLocker Audit Summary" -TitleBold -TitleSize 14

Write-Log "  Report exported to: $ExportPath" -Color Yellow

# --- Console Summary ---
Write-Log "--- Summary ---" -Color Cyan
Write-Log "  Total devices:            $($allDevices.Count)"
Write-Log "    Active:                 $activeCount"
Write-Log "    Inactive (>$InactiveDays days):   $inactiveCount" -Color $(if ($inactiveCount -gt 0) { 'Yellow' } else { 'Green' })
Write-Log "  With BitLocker key:       $($compliantDevices.Count)" -Color Green
Write-Log "  Missing BitLocker key:    $($missingDevices.Count)" -Color $(if ($missingDevices.Count -gt 0) { 'Red' } else { 'Green' })
Write-Log "    Active missing key:     $activeMissing" -Color $(if ($activeMissing -gt 0) { 'Red' } else { 'Green' })
$complianceRate = if ($activeCount -gt 0) { [math]::Round((($activeCount - $activeMissing) / $activeCount) * 100, 1) } else { 0 }
Write-Log "  Compliance rate (active): $complianceRate%" -Color $(if ($complianceRate -ge 95) { 'Green' } elseif ($complianceRate -ge 80) { 'Yellow' } else { 'Red' })

Disconnect-MgGraph | Out-Null
Write-Log "Done. Log saved to: $logFile" -Color Cyan
