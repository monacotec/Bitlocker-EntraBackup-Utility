<#
.SYNOPSIS
    Intune Remediation - REMEDIATION script: escrows BitLocker recovery keys to Entra ID.
.DESCRIPTION
    Backs up every RecoveryPassword protector on every encrypted volume to
    Entra ID via BackupToAAD-BitLockerKeyProtector, then verifies a success
    event (845) was written for each protector.

    Idempotent: re-escrowing an already-escrowed key is a no-op server-side.

    Intune Remediation settings:
      Run this script using the logged-on credentials : No  (runs as SYSTEM)
      Run script in 64-bit PowerShell                 : Yes
#>

$ErrorActionPreference = 'Stop'

$failures = [System.Collections.Generic.List[string]]::new()
$succeeded = 0
$startTime = Get-Date

try {
    $volumes = Get-BitLockerVolume | Where-Object {
        $_.VolumeStatus -ne 'FullyDecrypted' -and
        ($_.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')
    }

    if (-not $volumes) {
        Write-Output "Nothing to do: no encrypted volumes with RecoveryPassword protectors."
        exit 0
    }

    foreach ($vol in $volumes) {
        foreach ($kp in ($vol.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')) {
            try {
                BackupToAAD-BitLockerKeyProtector -MountPoint $vol.MountPoint -KeyProtectorId $kp.KeyProtectorId | Out-Null
                $succeeded++
                Write-Output "Escrowed $($vol.MountPoint) protector $($kp.KeyProtectorId)"
            }
            catch {
                $failures.Add("$($vol.MountPoint) $($kp.KeyProtectorId): $_")
            }
        }
    }

    # Verify: each attempt should have produced an 845 (success) event just now.
    Start-Sleep -Seconds 5
    $recent845 = 0
    try {
        $recent845 = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-BitLocker/BitLocker Management'
            Id        = 845
            StartTime = $startTime
        } -ErrorAction Stop).Count
    } catch { $recent845 = 0 }

    if ($failures.Count -gt 0) {
        Write-Output "FAILED protectors: $($failures -join '; ')"
        exit 1
    }
    if ($recent845 -lt $succeeded) {
        Write-Output "WARNING: $succeeded escrow call(s) returned OK but only $recent845 success event(s) logged."
        exit 1
    }

    Write-Output "SUCCESS: $succeeded protector(s) escrowed to Entra ID and verified via event 845."
    exit 0
}
catch {
    Write-Output "REMEDIATION ERROR: $_"
    exit 1
}
