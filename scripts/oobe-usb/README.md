# OOBE Provisioning USB

Builds a provisioning package (PPKG) that a tech inserts at the **first OOBE
screen** of a new laptop. It does two things:

1. **Blocks automatic device encryption** (`PreventDeviceEncryption = 1`) so the
   drive stays cleartext until the Intune BitLocker policy encrypts it —
   escrow-to-Entra first, XTS-AES 256, exactly as configured.
2. **Joins the machine to `pe.gipartners.com`** with a least-privilege join
   account. Hybrid Entra join then completes automatically via the existing
   SCP/GPO once Entra Connect syncs the computer object (30-min cycle).

Resulting new-build sequence:

```
OOBE + PPKG (no encryption, domain joined) -> reboot -> sign in on corp network
  -> Connect sync creates Entra object -> hybrid join completes
  -> GPO auto-enrolls into Intune -> BitLocker policy: escrow key THEN encrypt
```

## Build the package (one time)

1. Install **Windows Configuration Designer** (Microsoft Store, or part of the
   Windows ADK).
2. **Start a new project** > *Provision desktop devices* (wizard):
   - **Set up device**: device name `GI-%SERIAL%` (rename to the user-based
     convention after handoff), leave product key blank.
   - **Set up network**: skip (OFF) — machines are built on the wired corp network.
   - **Account management**: *Enroll into Active Directory*:
     - Domain: `pe.gipartners.com`
     - Account: the delegated join account (see Security below)
     - Password: its password
   - Skip *Add applications* and *Add certificates* (PDQ package handles apps).
3. Before exporting, click **Switch to advanced editor** and add the encryption
   block: **Runtime settings > ProvisioningCommands > PrimaryContext > Command**
   - **CommandFiles**: add `prevent-device-encryption.cmd` (this folder)
   - **CommandLine**: `cmd /c prevent-device-encryption.cmd`
   - ContinueInstall: True, RestartRequired: False
4. **Export > Provisioning package**:
   - Owner: **IT Admin**
   - **Encrypt package: Yes** — set a package password (the tech types it at
     apply time; this protects the embedded join credentials)
   - Build.
5. Copy the resulting `.ppkg` to the **root of a USB stick**.

## Use (per machine)

1. Unbox, connect to the wired corporate network, power on.
2. At the **first OOBE screen** (region/language), insert the USB stick.
3. Windows prompts "Is this package from a source you trust?" — tech enters the
   package password and confirms.
4. Machine applies settings, joins the domain, reboots. Remove the stick.
5. Verify before handoff (after ~30-60 min on network):
   - `dsregcmd /status` shows `DomainJoined: YES` and `AzureAdJoined: YES`
   - `Get-BitLockerVolume` shows `FullyDecrypted` until Intune policy lands,
     then encryption with protection ON
   - Audit log (Entra > Audit Logs, activity "Add BitLocker key to device")
     shows the key escrowed
6. Run the PDQ app-provisioning package as usual.

## Security notes

- **Join account**: use a dedicated service account with rights delegated ONLY
  to create/join computer objects in the target OU (Delegation of Control on
  the OU: "Create Computer objects" + reset password/write on computer
  objects). Never a Domain Admin. Rotate its password periodically — a PPKG
  rebuild takes two minutes.
- The `.ppkg` embeds those credentials — always export **encrypted**, keep the
  sticks physically controlled, and rebuild + re-issue if one goes missing.
- A machine that misses the PPKG simply falls back to today's behavior
  (auto-encrypted, key caught later by the Intune Remediation) — the safety
  net stays in place either way.
