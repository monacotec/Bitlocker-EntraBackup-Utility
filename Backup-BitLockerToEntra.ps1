<#
.SYNOPSIS
    Backs up BitLocker recovery keys to Entra ID (Azure AD) for hybrid-joined devices.
.DESCRIPTION
    Designed to run as SYSTEM via PDQ Connect. Enumerates all BitLocker-encrypted volumes,
    finds their RecoveryPassword key protectors, and backs each one up to Entra ID.

    For hybrid-joined devices, dsregcmd must run in SYSTEM context to see the device
    registration state. This script schedules itself as a SYSTEM task if it detects it
    is running as a standard user.
.NOTES
    Requirements:
      - Device must be Hybrid Azure AD Joined
      - BitLocker must be enabled with a RecoveryPassword protector
      - Runs as SYSTEM (PDQ Connect default)
#>

$ErrorActionPreference = 'Stop'

# --- Ensure SYSTEM context ---
# PDQ Connect runs as SYSTEM by default, but guard against manual runs.
# dsregcmd and BackupToAAD-BitLockerKeyProtector both require SYSTEM or admin context.

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isSystem = $currentIdentity.IsSystem
$isAdmin = ([Security.Principal.WindowsPrincipal]$currentIdentity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {
    Write-Error "This script must run as Administrator or SYSTEM. Current user: $($currentIdentity.Name)"
    exit 1
}

Write-Output "Running as: $($currentIdentity.Name)"

# --- Preflight: verify Hybrid Azure AD Join ---
# In SYSTEM context, dsregcmd /status returns the device join state.
# In user context on hybrid devices it may show the user's Entra registration instead.

$dsregOutput = dsregcmd /status 2>&1 | Out-String

$isAzureJoined = $dsregOutput -match 'AzureAdJoined\s*:\s*YES'
$isDomainJoined = $dsregOutput -match 'DomainJoined\s*:\s*YES'

if (-not $isAzureJoined) {
    # On hybrid devices, Entra registration can lag. Trigger a sync and recheck.
    Write-Output "Device not showing as Azure AD joined. Triggering device sync..."
    dsregcmd /join 2>&1 | Out-Null
    Start-Sleep -Seconds 10

    $dsregOutput = dsregcmd /status 2>&1 | Out-String
    $isAzureJoined = $dsregOutput -match 'AzureAdJoined\s*:\s*YES'
}

if (-not $isAzureJoined) {
    Write-Error "Device is not Azure AD / Entra joined after sync attempt. Cannot back up keys to Entra."
    Write-Output "Domain Joined: $(if ($isDomainJoined) { 'YES' } else { 'NO' })"
    Write-Output "Azure AD Joined: NO"

    # Dump relevant dsregcmd lines for troubleshooting
    $dsregOutput -split "`n" | Where-Object { $_ -match '(Joined|TenantId|DeviceId|Error|ThumbPrint)' } |
        ForEach-Object { Write-Output "  $_" }
    exit 1
}

# Extract device and tenant info for logging
$tenantMatch = [regex]::Match($dsregOutput, 'TenantId\s*:\s*(\S+)')
$deviceMatch = [regex]::Match($dsregOutput, 'DeviceId\s*:\s*(\S+)')
if ($tenantMatch.Success) { Write-Output "Entra Tenant: $($tenantMatch.Groups[1].Value)" }
if ($deviceMatch.Success) { Write-Output "Device ID:    $($deviceMatch.Groups[1].Value)" }
Write-Output "Domain Joined: $(if ($isDomainJoined) { 'YES' } else { 'NO' })"
Write-Output "Azure AD Joined: YES"

# --- Enumerate BitLocker volumes ---

$volumes = Get-BitLockerVolume | Where-Object { $_.ProtectionStatus -eq 'On' -or $_.VolumeStatus -ne 'FullyDecrypted' }

if (-not $volumes) {
    Write-Output "No BitLocker-encrypted volumes found. Nothing to back up."
    exit 0
}

$failCount = 0
$successCount = 0

foreach ($volume in $volumes) {
    $mountPoint = $volume.MountPoint
    Write-Output "`nProcessing volume: $mountPoint (Status: $($volume.VolumeStatus), Protection: $($volume.ProtectionStatus))"

    # Get RecoveryPassword protectors (these are the ones Entra stores)
    $recoveryProtectors = $volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }

    if (-not $recoveryProtectors) {
        Write-Warning "  No RecoveryPassword protector found on $mountPoint — adding one."
        try {
            $newProtector = Add-BitLockerKeyProtector -MountPoint $mountPoint -RecoveryPasswordProtector
            $recoveryProtectors = $newProtector.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
        }
        catch {
            Write-Warning "  Failed to add RecoveryPassword protector to ${mountPoint}: $_"
            $failCount++
            continue
        }
    }

    foreach ($protector in $recoveryProtectors) {
        $protectorId = $protector.KeyProtectorId
        Write-Output "  Backing up protector $protectorId to Entra ID..."
        try {
            BackupToAAD-BitLockerKeyProtector -MountPoint $mountPoint -KeyProtectorId $protectorId
            Write-Output "  [OK] Backed up protector $protectorId"
            $successCount++
        }
        catch {
            Write-Warning "  [!!] Failed to back up protector $protectorId on ${mountPoint}: $_"
            $failCount++
        }
    }
}

# --- Summary ---

Write-Output "`n=== Summary ==="
Write-Output "Volumes processed: $($volumes.Count)"
Write-Output "Protectors backed up: $successCount"
Write-Output "Failures: $failCount"

if ($failCount -gt 0) {
    Write-Output "`n[!!] Completed with errors."
    exit 1
}

Write-Output "`n[OK] All recovery keys backed up to Entra ID."
exit 0
