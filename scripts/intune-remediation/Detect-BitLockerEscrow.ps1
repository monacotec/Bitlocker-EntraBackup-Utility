<#
.SYNOPSIS
    Intune Remediation - DETECTION script for BitLocker key escrow to Entra ID.
.DESCRIPTION
    Exits 1 (non-compliant, triggers remediation) when any RecoveryPassword
    protector on an encrypted volume has no matching successful Entra backup
    event (Event 845 in the BitLocker Management log).

    Why event-based: escrow is a one-shot action with no queryable local state.
    Event 845 (success) / 846 (failure) are the only on-device records. If the
    log has rolled over, this errs toward re-escrow - which is harmless and
    idempotent.

    Root cause this addresses: Windows 11 24H2+ automatic device encryption
    encrypts new machines during OOBE, before Intune enrollment completes, so
    the policy's escrow-at-encryption-time trigger never fires.

    Intune Remediation settings:
      Run this script using the logged-on credentials : No  (runs as SYSTEM)
      Run script in 64-bit PowerShell                 : Yes
      Schedule                                        : Daily
#>

$ErrorActionPreference = 'Stop'

try {
    $volumes = Get-BitLockerVolume | Where-Object {
        $_.VolumeStatus -ne 'FullyDecrypted' -and
        ($_.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')
    }

    if (-not $volumes) {
        Write-Output "COMPLIANT: no encrypted volumes with RecoveryPassword protectors (nothing to escrow)."
        exit 0
    }

    # Collect successful-escrow events (845). Message contains the protector GUID.
    $successText = ''
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-BitLocker/BitLocker Management'
            Id      = 845
        } -ErrorAction Stop
        $successText = ($events | ForEach-Object { $_.Message }) -join "`n"
    } catch {
        # No 845 events at all -> nothing was ever escrowed
        $successText = ''
    }

    $unescrowed = [System.Collections.Generic.List[string]]::new()

    foreach ($vol in $volumes) {
        foreach ($kp in ($vol.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')) {
            $guid = $kp.KeyProtectorId.Trim('{}')
            if ($successText -notmatch [regex]::Escape($guid)) {
                $unescrowed.Add("$($vol.MountPoint) $($kp.KeyProtectorId)")
            }
        }
    }

    if ($unescrowed.Count -gt 0) {
        Write-Output "NON-COMPLIANT: no Entra backup success event for: $($unescrowed -join '; ')"
        exit 1
    }

    Write-Output "COMPLIANT: all RecoveryPassword protectors have a successful Entra backup event."
    exit 0
}
catch {
    # Fail toward remediation - escrow is idempotent and safe to re-run.
    Write-Output "DETECTION ERROR (treating as non-compliant): $_"
    exit 1
}
