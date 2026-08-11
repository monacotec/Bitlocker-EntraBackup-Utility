# Bitlocker-EntraBackup-Utility

PowerShell script that backs up BitLocker recovery keys to Entra ID (Azure AD) for hybrid-joined devices. Designed to be deployed at scale via PDQ Connect.

## Problem

On hybrid Azure AD joined devices, BitLocker recovery keys are often only stored in on-prem Active Directory. If a device needs recovery and AD is unreachable, the key is lost. This script ensures recovery keys are also escrowed to Entra ID.

## How It Works

1. Verifies the script is running as Administrator or SYSTEM
2. Checks the device's Hybrid Azure AD Join status via `dsregcmd /status`
3. If the device isn't showing as Entra-joined, triggers `dsregcmd /join` and retries
4. Enumerates all BitLocker-encrypted volumes
5. For each volume, finds `RecoveryPassword` key protectors (adds one if missing)
6. Backs up each protector to Entra ID via `BackupToAAD-BitLockerKeyProtector`

## Requirements

- Windows 10/11 with BitLocker enabled
- Device must be Hybrid Azure AD Joined (or Azure AD Joined)
- Must run as **SYSTEM** or **Administrator** — `dsregcmd /status` returns the device join state only in these contexts; a standard user sees their own Entra registration instead

## Usage

### PDQ Connect (recommended)

1. Create a new script deployment in PDQ Connect
2. Paste or reference `Backup-BitLockerToEntra.ps1`
3. Target your device groups — PDQ Connect runs scripts as SYSTEM by default

### Manual (testing)

Run from an elevated PowerShell prompt:

```powershell
.\Backup-BitLockerToEntra.ps1
```

## Output

The script writes structured output for PDQ Connect logging:

```
Running as: NT AUTHORITY\SYSTEM
Entra Tenant: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Device ID:    xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Domain Joined: YES
Azure AD Joined: YES

Processing volume: C: (Status: FullyEncrypted, Protection: On)
  Backing up protector {GUID} to Entra ID...
  [OK] Backed up protector {GUID}

=== Summary ===
Volumes processed: 1
Protectors backed up: 1
Failures: 0

[OK] All recovery keys backed up to Entra ID.
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All keys backed up successfully (or no BitLocker volumes found) |
| 1 | One or more failures — check the log output for details |

## Intune Remediation (systemic fix — recommended)

Windows 11 24H2+ **automatic device encryption** encrypts new machines during
OOBE, *before* hybrid join and Intune enrollment complete. The Intune BitLocker
policy escrows keys only at encryption time, so pre-encrypted machines are
silently skipped and BitLocker never retries a missed/failed escrow. Every new
laptop loses this race (confirmed on GIBSMAR-X1: hybrid joined 16:31 UTC,
Intune enrolled 17:59 UTC, already encrypted, zero keys escrowed).

The fix is `scripts/intune-remediation/` — a Remediation pair that makes escrow
a converging state instead of a one-shot event:

- `Detect-BitLockerEscrow.ps1` — non-compliant when any RecoveryPassword
  protector lacks a successful Entra backup event (Event 845)
- `Remediate-BitLockerEscrow.ps1` — runs `BackupToAAD-BitLockerKeyProtector`
  for every protector and verifies the 845 event landed

Setup: Intune > **Devices > Scripts and remediations > Remediations > Create**

| Setting | Value |
|---|---|
| Detection script | `Detect-BitLockerEscrow.ps1` |
| Remediation script | `Remediate-BitLockerEscrow.ps1` |
| Run using logged-on credentials | **No** (SYSTEM) |
| Run in 64-bit PowerShell | **Yes** |
| Schedule | Daily |
| Assignment | All Windows workstations |

Requires Windows Enterprise/Education (E3+) or Pro with the Remediations
license check satisfied.

## Scripts

| Script | Where it runs | Purpose |
|---|---|---|
| `Backup-BitLockerToEntra.ps1` | Device (PDQ Connect, backup method) | One-shot escrow of all recovery keys |
| `scripts/bitlocker/Get-DevicesMissingBitLockerKeys.ps1` | Admin workstation | Tenant-wide audit: devices vs escrowed keys (XLSX report) |
| `scripts/bitlocker/Get-DeviceEscrowStatus.ps1` | Admin workstation | Server-side escrow-chain trace for one device (no device access) |
| `scripts/bitlocker/Get-BitLockerEscrowDiagnostics.ps1` | Device (PDQ Connect) | On-device evidence collection (escrow events 845/846, timelines) |
| `scripts/intune-remediation/Detect-BitLockerEscrow.ps1` | Intune Remediation | Detects protectors never escrowed to Entra |
| `scripts/intune-remediation/Remediate-BitLockerEscrow.ps1` | Intune Remediation | Re-escrows and verifies via event 845 |

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Device is not Azure AD / Entra joined" | Device hasn't completed hybrid join registration | Run `dsregcmd /join` as SYSTEM and verify with `dsregcmd /status` |
| "must run as Administrator or SYSTEM" | Script launched by a standard user | Run via PDQ Connect or an elevated prompt |
| Backup fails with access error | Stale device certificate or broken trust | Re-register the device: `dsregcmd /leave` then `dsregcmd /join`, or rejoin the domain |
| No RecoveryPassword protector found | Volume uses TPM-only protection | Script auto-adds a RecoveryPassword protector |
