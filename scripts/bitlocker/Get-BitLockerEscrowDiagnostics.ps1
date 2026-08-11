<#
.SYNOPSIS
    Collects evidence to trace why a device failed to escrow its BitLocker key to Entra ID.
.DESCRIPTION
    Run as SYSTEM via PDQ Connect (or an elevated prompt) on the affected device.
    Gathers the full escrow dependency chain with timestamps so the broken link is visible:

      1. BitLocker volume + protector state (and protector types)
      2. BitLocker Management event log - escrow success (845) / failure (846) events
      3. Encryption timeline from the BitLocker-API event log
      4. Hybrid join state (dsregcmd) and when the device registered
      5. Intune (MDM) enrollment state and enrollment time
      6. BitLocker CSP policy values actually delivered to the device
      7. TPM state

    Output is plain text to stdout (PDQ Connect captures it) and mirrored to
    C:\GI\BitLockerEscrowDiag_<computername>_<timestamp>.txt
#>

$ErrorActionPreference = 'Continue'   # diagnostics: collect everything, fail nothing

$outDir = 'C:\GI'
if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }
$outFile = Join-Path $outDir "BitLockerEscrowDiag_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

function Out-Section {
    param([string]$Title)
    $bar = '=' * 70
    Write-Output "`n$bar`n== $Title`n$bar"
}

$report = & {

    Out-Section "DEVICE: $env:COMPUTERNAME  |  Collected: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output "Running as: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Write-Output "OS: $((Get-CimInstance Win32_OperatingSystem).Caption) $((Get-CimInstance Win32_OperatingSystem).Version)"
    Write-Output "OS Install Date: $((Get-CimInstance Win32_OperatingSystem).InstallDate)"

    # --- 1. BitLocker state ---
    Out-Section "1. BITLOCKER VOLUME STATE"
    foreach ($vol in Get-BitLockerVolume) {
        Write-Output "MountPoint:       $($vol.MountPoint)"
        Write-Output "VolumeStatus:     $($vol.VolumeStatus)"
        Write-Output "ProtectionStatus: $($vol.ProtectionStatus)"
        Write-Output "EncryptionMethod: $($vol.EncryptionMethod)"
        Write-Output "EncryptionPct:    $($vol.EncryptionPercentage)"
        foreach ($kp in $vol.KeyProtector) {
            Write-Output "  Protector: $($kp.KeyProtectorType)  Id: $($kp.KeyProtectorId)"
        }
        Write-Output ""
    }

    # --- 2. Escrow events: 845 = backed up to Azure AD OK, 846 = backup FAILED ---
    Out-Section "2. ESCROW EVENTS (BitLocker Management log: 845=success, 846=failure)"
    try {
        $mgmtEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-BitLocker/BitLocker Management'
        } -ErrorAction Stop | Sort-Object TimeCreated
        if ($mgmtEvents) {
            foreach ($e in $mgmtEvents) {
                Write-Output "[$($e.TimeCreated)] Event $($e.Id): $($e.Message -replace '\s+', ' ')"
            }
        } else {
            Write-Output "NO EVENTS in BitLocker Management log - escrow was NEVER ATTEMPTED."
            Write-Output "This means the MDM policy trigger never fired (device not enrolled/policy not applied at encryption time)."
        }
    } catch {
        Write-Output "Could not read BitLocker Management log: $_"
        Write-Output "If the log doesn't exist or is empty, escrow was never attempted."
    }

    # --- 3. Encryption timeline (when was the volume actually encrypted?) ---
    Out-Section "3. ENCRYPTION TIMELINE (BitLocker-API log, last 30 events)"
    try {
        Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-BitLocker/BitLocker Operational' } -MaxEvents 30 -ErrorAction Stop |
            Sort-Object TimeCreated |
            ForEach-Object { Write-Output "[$($_.TimeCreated)] Event $($_.Id): $(($_.Message -split "`n")[0])" }
    } catch {
        Write-Output "BitLocker Operational log unavailable: $_"
    }

    # --- 4. Hybrid join state ---
    Out-Section "4. ENTRA JOIN STATE (dsregcmd /status)"
    $dsreg = dsregcmd /status 2>&1 | Out-String
    $dsreg -split "`n" | Where-Object {
        $_ -match '(AzureAdJoined|DomainJoined|EnterpriseJoined|WorkplaceJoined|TenantId|DeviceId|DeviceCertificateValidity|AzureAdPrt\s|MdmUrl|Mdm\s)'
    } | ForEach-Object { Write-Output $_.Trim() }

    # --- 5. Intune enrollment ---
    Out-Section "5. INTUNE (MDM) ENROLLMENT"
    $enrollFound = $false
    $enrollRoot = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (Test-Path $enrollRoot) {
        foreach ($key in Get-ChildItem $enrollRoot) {
            $props = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
            if ($props.ProviderID -eq 'MS DM Server') {
                $enrollFound = $true
                Write-Output "Enrollment GUID:  $($key.PSChildName)"
                Write-Output "UPN:              $($props.UPN)"
                Write-Output "EnrollmentState:  $($props.EnrollmentState)"
                Write-Output "EnrollmentType:   $($props.EnrollmentType)"
                # Enrollment time from the scheduled task creation, best-effort
                $dmwTask = Get-ScheduledTask -TaskPath "\Microsoft\Windows\EnterpriseMgmt\$($key.PSChildName)\" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($dmwTask) { Write-Output "EnterpriseMgmt scheduled tasks present: YES" }
            }
        }
    }
    if (-not $enrollFound) {
        Write-Output "NO Intune enrollment found (no 'MS DM Server' provider under HKLM\SOFTWARE\Microsoft\Enrollments)."
        Write-Output "ROOT CAUSE CANDIDATE: device is not MDM-enrolled, so the BitLocker policy never reaches it."
    }

    # --- 6. BitLocker CSP policy actually delivered ---
    Out-Section "6. BITLOCKER CSP POLICY VALUES ON DEVICE (PolicyManager)"
    $cspPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker'
    if (Test-Path $cspPath) {
        Get-ItemProperty $cspPath | Select-Object * -ExcludeProperty PS* | Format-List | Out-String | Write-Output
    } else {
        Write-Output "NO BitLocker CSP policy node found at $cspPath"
        Write-Output "ROOT CAUSE CANDIDATE: the Intune disk encryption policy has NOT been delivered to this device."
    }

    # --- 7. TPM ---
    Out-Section "7. TPM STATE"
    try {
        $tpm = Get-Tpm
        Write-Output "TpmPresent: $($tpm.TpmPresent)  TpmReady: $($tpm.TpmReady)  TpmEnabled: $($tpm.TpmEnabled)  TpmActivated: $($tpm.TpmActivated)"
    } catch {
        Write-Output "Get-Tpm failed: $_"
    }

    # --- Verdict hints ---
    Out-Section "INTERPRETATION GUIDE"
    Write-Output "Match the timestamps: protector creation (section 3) vs hybrid join vs MDM enrollment."
    Write-Output " - Section 2 has an 846 event  -> escrow attempted and FAILED; the error code in the event is the root cause."
    Write-Output " - Section 2 empty             -> escrow never attempted; encryption happened before policy/enrollment."
    Write-Output " - Section 5 empty             -> device never enrolled in Intune; fix auto-enrollment (GPO 'Enable automatic MDM enrollment using default Azure AD credentials')."
    Write-Output " - Section 6 empty             -> enrolled but policy not assigned/delivered; check Intune assignment groups."
    Write-Output " - Encrypted before join/enroll -> imaging/OEM encrypts first; policy only escrows at encryption time. Fix the build sequence or rotate keys post-build."
}

$report | Tee-Object -FilePath $outFile
Write-Output "`nDiagnostics saved to: $outFile"
