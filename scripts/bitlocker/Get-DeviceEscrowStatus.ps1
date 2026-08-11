#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Server-side trace of the BitLocker escrow chain for a single device - no device access needed.

.DESCRIPTION
    Pulls everything Graph knows about one device and lines it up as a timeline:

      1. Entra device object     - registration time, trust type, enabled state
      2. Intune managed device   - enrollment time, last check-in, isEncrypted, management agent
      3. BitLocker recovery keys - any keys escrowed for this device, and when
      4. Verdict                 - which link of the escrow chain is broken

    Graph permissions used (delegated, admin account):
      Device.Read.All
      BitLockerKey.ReadBasic.All          (key metadata only - never reads key material)
      DeviceManagementManagedDevices.Read.All

.PARAMETER DeviceName
    Display name of the device, e.g. GIBSMAR-X1.

.PARAMETER TenantId
    Optional tenant ID.

.EXAMPLE
    .\Get-DeviceEscrowStatus.ps1 -DeviceName GIBSMAR-X1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$DeviceName,

    [Parameter()]
    [string]$TenantId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scopes = @(
    'Device.Read.All',
    'BitLockerKey.ReadBasic.All',
    'DeviceManagementManagedDevices.Read.All'
)

$connectParams = @{ Scopes = $scopes; NoWelcome = $true }
if ($TenantId) { $connectParams['TenantId'] = $TenantId }

# Clear any cached Graph session so the browser prompts for account selection
try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}

Write-Host "Connecting to Microsoft Graph (select your admin account in the browser)..." -ForegroundColor Cyan
Connect-MgGraph @connectParams
$context = Get-MgContext
Write-Host "Connected as $($context.Account)" -ForegroundColor Green

$issues = [System.Collections.Generic.List[string]]::new()
$timeline = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Timeline {
    param([string]$Event, $When)
    if ($When) {
        $timeline.Add([PSCustomObject]@{ When = [datetime]$When; Event = $Event })
    }
}

# --- 1. Entra device object ---
Write-Host "`n=== 1. Entra device object ===" -ForegroundColor Cyan
$entraDevices = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/devices?`$filter=displayName eq '$DeviceName'").value

if (-not $entraDevices) {
    Write-Host "[!!] No Entra device object named '$DeviceName' found." -ForegroundColor Red
    Disconnect-MgGraph | Out-Null
    exit 1
}
if ($entraDevices.Count -gt 1) {
    Write-Host "[!!] $($entraDevices.Count) Entra objects share this name - duplicate registrations (stale + current):" -ForegroundColor Yellow
}

foreach ($d in $entraDevices) {
    Write-Host "  displayName:       $($d.displayName)"
    Write-Host "  deviceId:          $($d.deviceId)"
    Write-Host "  trustType:         $($d.trustType)  $(if ($d.trustType -eq 'ServerAd') { '(hybrid joined)' } elseif ($d.trustType -eq 'Workplace') { '(REGISTERED ONLY - not joined!)' })"
    Write-Host "  accountEnabled:    $($d.accountEnabled)"
    Write-Host "  registered:        $($d.registrationDateTime)"
    Write-Host "  lastSignIn:        $($d.approximateLastSignInDateTime)"
    Write-Host "  mdm:               $($d.managementType ?? 'n/a')"
    Write-Host "  ---"
    Add-Timeline -Event "Entra registration ($($d.trustType), deviceId $($d.deviceId))" -When $d.registrationDateTime
    if ($d.trustType -eq 'Workplace') {
        $issues.Add("Entra object $($d.deviceId) is 'Workplace' (registered, not joined) - BitLocker escrow requires hybrid/Entra JOIN.")
    }
}

# --- 2. Intune managed device ---
Write-Host "`n=== 2. Intune managed device record ===" -ForegroundColor Cyan
$managed = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=deviceName eq '$DeviceName'").value

if (-not $managed) {
    Write-Host "[!!] NOT ENROLLED IN INTUNE - no managedDevice record. The BitLocker policy can never reach this device." -ForegroundColor Red
    $issues.Add("Device is not Intune-enrolled. Root cause candidate: MDM auto-enrollment did not run. Check the auto-enrollment GPO and the user's Intune license.")
} else {
    foreach ($m in $managed) {
        Write-Host "  intuneDeviceId:    $($m.id)"
        Write-Host "  azureADDeviceId:   $($m.azureADDeviceId)"
        Write-Host "  enrolled:          $($m.enrolledDateTime)"
        Write-Host "  lastSync:          $($m.lastSyncDateTime)"
        Write-Host "  enrollmentType:    $($m.deviceEnrollmentType)"
        Write-Host "  managementAgent:   $($m.managementAgent)"
        Write-Host "  complianceState:   $($m.complianceState)"
        $encColor = if ($m.isEncrypted) { 'Green' } else { 'Red' }
        Write-Host "  isEncrypted:       $($m.isEncrypted)" -ForegroundColor $encColor
        Write-Host "  ---"
        Add-Timeline -Event "Intune enrollment ($($m.deviceEnrollmentType))" -When $m.enrolledDateTime
        Add-Timeline -Event "Last Intune check-in" -When $m.lastSyncDateTime

        if (-not $m.isEncrypted) {
            $issues.Add("Intune reports the device is NOT encrypted - there is no key to escrow yet. The encryption policy itself has not taken effect (check silent-encryption prerequisites: TPM ready, no pre-boot PIN requirement, user auto-enrolled).")
        }
        $staleDays = ((Get-Date) - [datetime]$m.lastSyncDateTime).TotalDays
        if ($staleDays -gt 7) {
            $issues.Add("Device has not checked in for $([math]::Round($staleDays)) days - policy changes and remote actions will not land until it syncs.")
        }
    }
}

# --- 3. BitLocker recovery keys escrowed for this device ---
Write-Host "`n=== 3. BitLocker keys escrowed in Entra for this device ===" -ForegroundColor Cyan
$keyCount = 0
foreach ($d in $entraDevices) {
    $keys = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/informationProtection/bitlocker/recoveryKeys?`$filter=deviceId eq '$($d.deviceId)'").value
    foreach ($k in $keys) {
        $keyCount++
        Write-Host "  [OK] Key $($k.id)  created $($k.createdDateTime)  volumeType $($k.volumeType)" -ForegroundColor Green
        Add-Timeline -Event "BitLocker key escrowed (key $($k.id))" -When $k.createdDateTime
    }
}
if ($keyCount -eq 0) {
    Write-Host "  [!!] ZERO keys escrowed for this device." -ForegroundColor Red
}

# --- 4. Timeline + verdict ---
Write-Host "`n=== 4. Timeline ===" -ForegroundColor Cyan
$timeline | Sort-Object When | Format-Table @{L='When (UTC)';E={$_.When.ToString('yyyy-MM-dd HH:mm:ss')}}, Event -AutoSize

Write-Host "=== Verdict ===" -ForegroundColor Cyan
if ($issues.Count -eq 0 -and $keyCount -gt 0) {
    Write-Host "[OK] Keys are escrowed and the chain looks healthy." -ForegroundColor Green
} elseif ($issues.Count -eq 0) {
    Write-Host "[!!] Chain looks intact server-side (hybrid joined, Intune enrolled, encrypted) but no key is escrowed." -ForegroundColor Yellow
    Write-Host "     The failure detail is on the device: BitLocker Management event log (845/846)." -ForegroundColor Yellow
    Write-Host "     -> Intune > Devices > $DeviceName > 'Collect diagnostics' pulls those logs remotely" -ForegroundColor Yellow
    Write-Host "        next check-in, then download from the portal (Monitor > Device diagnostics)." -ForegroundColor Yellow
    Write-Host "     -> Or trigger escrow now, Intune-native: Devices > $DeviceName > 'Rotate BitLocker keys'." -ForegroundColor Yellow
} else {
    $n = 0
    foreach ($i in $issues) { $n++; Write-Host "[$n] $i" -ForegroundColor Red }
}

Disconnect-MgGraph | Out-Null
