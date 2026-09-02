# Runbook: Build the OOBE Provisioning USB

**Purpose:** produce a USB stick that, inserted at the first OOBE screen of a new
laptop, (1) blocks Windows 11 automatic device encryption and (2) joins the
machine to `pe.gipartners.com` — so hybrid join, Intune enrollment, and
escrow-first BitLocker encryption happen in the intended order.

**Audience:** IT admin building/maintaining the stick (Part A–C, one-time),
deployment tech using it (Part D, per machine).

**Time:** ~45 min one-time build; ~2 min per machine in the field.

---

## Part A — One-time prerequisites

### A1. Create the delegated domain-join account

Run `New-HybridJoinAccount.ps1` (this folder) on a DC or admin workstation with
RSAT, as a domain admin. It creates **`hybridjoin@gipartners.com`** (sAM
`PE\hybridjoin`) with password-never-expires, and applies the least-privilege
delegation on the workstation OU (create computer objects; reset password and
write the join attributes on descendant computer objects only).

```powershell
.\New-HybridJoinAccount.ps1
```

The script is idempotent — re-run any time to verify, or audit without touching
anything:

```powershell
.\New-HybridJoinAccount.ps1 -VerifyOnly
```

Annual rotation: `.\New-HybridJoinAccount.ps1 -ResetPassword`, then rebuild the
PPKG (Part B).

**Harden it — deny all logon types except network.** User Rights Assignment is
NOT cumulative across GPOs (the winning GPO replaces the list), so first check
whether an existing GPO already defines the deny rights and add the account
there if so:

```powershell
Get-GPO -All | ForEach-Object { if ((Get-GPOReport -Guid $_.Id -ReportType Xml) -match 'SeDenyInteractiveLogonRight|SeDenyRemoteInteractiveLogonRight') { $_.DisplayName } }
```

Otherwise, in GPMC create `GI - Service Account Logon Restrictions` linked at
the domain root, then under Computer Configuration > Policies > Windows
Settings > Security Settings > Local Policies > **User Rights Assignment** add
`PE\hybridjoin` to all four:

- Deny log on locally
- Deny log on through Remote Desktop Services
- Deny log on as a batch job
- Deny log on as a service

Never add it to **"Deny access to this computer from the network"** — the
PPKG domain join authenticates to the DCs as a network logon and would break.

Verify: `gpresult /scope computer /h C:\GI\gpresult.html` on any refreshed
workstation shows the account in all four deny rights, winning GPO as expected;
a console sign-in attempt as `PE\hybridjoin` is refused.

### A2. Where joined computers land (critical)

Each package pins its landing OU explicitly via the advanced-editor setting
**Accounts > ComputerAccount > AccountOU** (the wizard doesn't expose it, the
advanced editor does — see B9):

- GI Partners package: `OU=Computers,OU=GI Partners,DC=pe,DC=gipartners,DC=com`
- GI Property package: `OU=Computers,OU=GI Property Management,DC=pe,DC=gipartners,DC=com`

The delegation covers both OUs (script defaults), and both must be in Entra
Connect sync scope and carry the auto-enrollment + SCP GPOs — if sync skips
the OU, the Entra object is never created and hybrid join silently never
completes.

As a safety net for any join that omits AccountOU, keep the domain's default
computers container redirected to the majority OU (verify with
`(Get-ADDomain).ComputersContainer`):

```bash
redircmp "OU=Computers,OU=GI Partners,DC=pe,DC=gipartners,DC=com"
```

### A3. Install Windows Configuration Designer

On your admin workstation: Microsoft Store > **Windows Configuration
Designer** (or the ADK's Imaging and Configuration Designer feature).

### A4. Gather materials

- USB stick, 1 GB+, FAT32 or NTFS, dedicated to this purpose, labeled
- `prevent-device-encryption.cmd` from this folder of the repo

---

## Part B — Build the provisioning package

1. Open Windows Configuration Designer > **Provision desktop devices**.
2. Project name: `GI-OOBE-Provisioning` (store the project in a secured location —
   the project file retains the join password).
3. **Set up device**
   - Device name: `GI-%SERIAL%` (unique per machine; rename to the user-based
     convention at handoff)
   - Product key: leave blank
   - Configure for shared use: Off
   - Remove pre-installed software: Off
4. **Set up network**: toggle **Off** (builds happen on the wired corp network;
   Wi-Fi profiles don't belong on the stick).
5. **Account management**: **Enroll into Active Directory**
   - Domain: `pe.gipartners.com`
   - User name: `PE\hybridjoin`
   - Password: (the A1 password)
6. **Add applications**: skip — the PDQ package owns app installs.
7. **Add certificates**: skip.
8. **Switch to advanced editor** (link at bottom-left; say Yes to the warning).
9. Advanced editor > **Runtime settings > ProvisioningCommands**:
   - Current WCD builds show **DeviceContext**:
     - **CommandFiles**: browse to `prevent-device-encryption.cmd`
     - **CommandLine**: `cmd /c prevent-device-encryption.cmd`
   - Older builds show **PrimaryContext > Command** instead: same two values,
     plus **ContinueInstall**: True and **RestartRequired**: False
   Then still in the advanced editor, pin the landing OU:
   **Runtime settings > Accounts > ComputerAccount > AccountOU** = the DN for
   this package (see A2). Commit with Enter/Tab and confirm it appears under
   Selected customizations.
10. **Export > Provisioning package**:
    - Owner: **IT Admin**
    - Version: bump on every rebuild
    - **Encrypt package: checked** — set the package password (this is what the
      tech types in the field; it protects the embedded join credential)
    - Do NOT also select a signing cert unless you already manage one
    - Build. Note the output folder.

### B2. Second package — GI Property Management

Same build, three differences:

| Setting | GI Partners package | GI Property package |
|---|---|---|
| Project / package name | `GI-OOBE-Provisioning` | `GIPM-OOBE-Provisioning` |
| Device name | `GI-%SERIAL%` | `GIPM-%SERIAL%` |
| AccountOU (advanced editor) | `OU=Computers,OU=GI Partners,...` | `OU=Computers,OU=GI Property Management,DC=pe,DC=gipartners,DC=com` |

Everything else is identical: same domain, same `PE\hybridjoin` credential,
same `prevent-device-encryption.cmd` ProvisioningCommand, encrypted export.
Use a separate stick labeled `GIPM OOBE v1.0` — a tech grabbing a stick must
not have to remember which package is on it.

## Part C — Prepare the USB

1. Copy the `.ppkg` to the **root** of the USB stick. Nothing else required.
2. Label the stick physically (e.g. `GI OOBE v1.0`).
3. Log the stick: who holds it, package version, build date.
4. Store the package password in the IT password manager — **never** on a label
   or a file on the stick.

---

## Part D — Field procedure (per machine)

1. Unbox, dock/connect **wired corporate network**, power on.
2. At the **first OOBE screen** (region/language selection), insert the USB stick.
3. Windows detects the package: *"Is this package from a source you trust?"* —
   choose **Yes, add it**, enter the package password.
4. Wait for it to apply. The machine joins `pe.gipartners.com` and **reboots**.
   Remove the stick during the reboot.
5. At the Windows sign-in screen, sign in with domain credentials
   (Other user > `PE\<account>`). **Do not** add a work account during any OOBE
   prompt — that creates the duplicate Workplace object in Entra.
6. Run the PDQ Connect app-provisioning package as usual.

### D2. Verification before handoff (allow 30–60 min on network)

| Check | Command | Expect |
|---|---|---|
| Not auto-encrypted | `Get-BitLockerVolume -MountPoint C:` | `FullyDecrypted` at first; encrypted with `Protection On` only after Intune policy lands |
| Block flag present | `reg query HKLM\SYSTEM\CurrentControlSet\Control\BitLocker /v PreventDeviceEncryption` | `0x1` |
| Domain join | `dsregcmd /status` | `DomainJoined: YES` |
| Hybrid join | `dsregcmd /status` | `AzureAdJoined: YES` (after the next Connect sync cycle — up to 30 min; admin can force with `Start-ADSyncSyncCycle -PolicyType Delta` on VMHOST-APP01) |
| Intune enrolled | Intune portal > Devices | Device present, co-management enrollment |
| Key escrowed | Entra > Audit Logs, activity "Add BitLocker key to device" (or run `Get-DeviceEscrowStatus.ps1 -DeviceName <name>`) | One key event after encryption |

A machine is **not ready to ship** until the last row is green.

---

## Part E — Maintenance

| Event | Action |
|---|---|
| Join-account password rotation (do annually) | Reset in AD, rebuild the PPKG (Part B step 5 + 10, bump version), re-copy to all sticks, retire old `.ppkg` files |
| Stick lost/stolen | Package is encrypted, but rotate `hybridjoin`'s password immediately (`New-HybridJoinAccount.ps1 -ResetPassword`) and rebuild anyway |
| New Windows build misbehaves at OOBE | Re-test the stick on one machine before the next batch; PPKG format is stable but OOBE prompts shift between releases |
| Machine built without the stick | No harm — it auto-encrypts at 128-bit like before, and the Intune Remediation escrows its key within a day. Optionally decrypt (`Disable-BitLocker -MountPoint C:`) so policy re-encrypts at XTS-256 |

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| No trust prompt when stick inserted | Package not at USB root, or inserted after OOBE progressed | Re-seat at the very first screen; power-cycle if needed |
| "Package couldn't be applied" | Wrong package password, or corrupted copy | Re-enter; re-copy the `.ppkg` |
| Domain join fails during apply | No line of sight to a DC (not on wired corp network), or `hybridjoin` locked/expired | Fix network first; run `New-HybridJoinAccount.ps1 -VerifyOnly` |
| `AzureAdJoined: NO` an hour after join | Computer object outside Connect sync scope (see A2), or sync stalled | Verify OU/scope; check Connect sync health on VMHOST-APP01 |
| Machine encrypts immediately anyway | Command step missing from package (step 9 skipped) | Verify with the reg query in D2; rebuild package |
