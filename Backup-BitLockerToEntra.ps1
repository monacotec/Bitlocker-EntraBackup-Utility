<#
.SYNOPSIS
    Backs up BitLocker recovery keys to Entra ID (Azure AD) for hybrid-joined devices.
.DESCRIPTION
    Designed to run as SYSTEM via PDQ Connect. Enumerates all BitLocker-encrypted volumes,
    finds their RecoveryPassword key protectors, and backs each one up to Entra ID.
.NOTES
    Requirements:
      - Device must be Hybrid Azure AD Joined
      - BitLocker must be enabled with a RecoveryPassword protector
      - Runs as SYSTEM (PDQ Connect default)
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

# --- Preflight checks ---

# Verify the device is Entra-registered (Hybrid or Azure AD Joined)
$dsregStatus = dsregcmd /status
$isAzureJoined = $dsregStatus | Select-String 'AzureAdJoined\s*:\s*YES'
if (-not $isAzureJoined) {
    Write-Error "Device is not Azure AD / Entra joined. Cannot back up keys to Entra."
    exit 1
}

# Get all BitLocker-enabled volumes
$volumes = Get-BitLockerVolume | Where-Object { $_.ProtectionStatus -eq 'On' -or $_.VolumeStatus -ne 'FullyDecrypted' }

if (-not $volumes) {
    Write-Output "No BitLocker-encrypted volumes found. Nothing to back up."
    exit 0
}

$failCount = 0
$successCount = 0

foreach ($volume in $volumes) {
    $mountPoint = $volume.MountPoint
    Write-Output "Processing volume: $mountPoint"

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
            Write-Output "  Successfully backed up protector $protectorId"
            $successCount++
        }
        catch {
            Write-Warning "  Failed to back up protector $protectorId on ${mountPoint}: $_"
            $failCount++
        }
    }
}

Write-Output "`n--- Summary ---"
Write-Output "Succeeded: $successCount"
Write-Output "Failed:    $failCount"

if ($failCount -gt 0) {
    exit 1
}

exit 0
