#Requires -Version 7.0
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Creates and delegates the hybridjoin@gipartners.com domain-join service account
    used by the OOBE provisioning package (see RUNBOOK.md Part A).

.DESCRIPTION
    Idempotent create-or-verify:
      Step 1 - service account exists with correct settings (enabled, password never
               expires, cannot change password, UPN)
      Step 2 - target OU exists
      Step 3 - least-privilege delegation ACEs on the OU:
                 * Create computer objects (this OU and below)
                 * On descendant computer objects: Reset Password, write
                   pwdLastSet / dNSHostName / servicePrincipalName /
                   sAMAccountName / userAccountControl, and the two validated writes
    Re-running after success prints all green. -VerifyOnly checks everything and
    mutates nothing (exit 1 with a red issue list on any gap).

    Run as a Domain Admin (or an account with rights to create users and edit the
    OU ACL) on a machine with RSAT ActiveDirectory.

.PARAMETER AccountName
    sAMAccountName of the service account. Default: hybridjoin

.PARAMETER UpnSuffix
    UPN suffix. Default: gipartners.com  (=> hybridjoin@gipartners.com)

.PARAMETER OU
    Distinguished name of the OU where joined computers land (see RUNBOOK A2 /
    redircmp). Delegation is applied here. Default: the Workstations OU in
    pe.gipartners.com.

.PARAMETER AccountOU
    OU where the service account itself is created (and moved to, if it exists
    elsewhere). Default: OU=Service Accounts,OU=GI Partners,DC=pe,DC=gipartners,DC=com

.PARAMETER AccountPassword
    SecureString password for account creation / -ResetPassword. Prompted if omitted
    when needed.

.PARAMETER ResetPassword
    Also reset the password of an existing account (use at rotation time; rebuild
    the PPKG afterward).

.PARAMETER VerifyOnly
    Check everything, change nothing. Exit 0 all green, exit 1 with issue list.

.EXAMPLE
    .\New-HybridJoinAccount.ps1
    .\New-HybridJoinAccount.ps1 -VerifyOnly
    .\New-HybridJoinAccount.ps1 -ResetPassword   # annual rotation, then rebuild PPKG
#>

[CmdletBinding()]
param(
    [Parameter()] [string]$AccountName = 'hybridjoin',
    [Parameter()] [string]$UpnSuffix = 'gipartners.com',
    [Parameter()] [string]$OU = 'OU=Workstations,OU=GI Partners,DC=pe,DC=gipartners,DC=com',
    [Parameter()] [string]$AccountOU = 'OU=Service Accounts,OU=GI Partners,DC=pe,DC=gipartners,DC=com',
    [Parameter()] [securestring]$AccountPassword,
    [Parameter()] [switch]$ResetPassword,
    [Parameter()] [switch]$VerifyOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Logging ---
$logDir = 'C:\GI'
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
$logFile = Join-Path $logDir "HybridJoinAccount_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Color = 'White')
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $Message"
    Write-Host $Message -ForegroundColor $Color
}

$issues = [System.Collections.Generic.List[string]]::new()
$upn = "$AccountName@$UpnSuffix"

$domain = Get-ADDomain
$netbios = $domain.NetBIOSName
Write-Log "Domain: $($domain.DNSRoot) ($netbios)   Mode: $(if ($VerifyOnly) { 'VERIFY ONLY' } else { 'provision' })" -Color Yellow
Write-Log "Log: $logFile"

# --- Step 1: service account ---
Write-Log "`n=== Step 1: service account $upn ===" -Color Cyan

$user = Get-ADUser -Filter "sAMAccountName -eq '$AccountName'" -Properties PasswordNeverExpires, CannotChangePassword, Description, Enabled

# The account's home OU must exist before we can create or move into it
$accountOuObj = $null
try {
    $accountOuObj = Get-ADOrganizationalUnit -Identity $AccountOU
}
catch {
    Write-Log "[!!] Account OU not found: $AccountOU" -Color Red
    $issues.Add("Account OU missing: $AccountOU")
}

if (-not $user) {
    if ($VerifyOnly) {
        Write-Log "[!!] Account $AccountName does not exist." -Color Red
        $issues.Add("Account $AccountName missing")
    }
    elseif (-not $accountOuObj) {
        Write-Log "[!!] Cannot create $AccountName - account OU is missing." -Color Red
        $issues.Add("Account $AccountName not created (OU missing)")
    }
    else {
        if (-not $AccountPassword) { $AccountPassword = Read-Host -AsSecureString "Password for new account $upn" }
        New-ADUser -Name $AccountName -SamAccountName $AccountName -UserPrincipalName $upn `
            -AccountPassword $AccountPassword -Enabled $true `
            -PasswordNeverExpires $true -CannotChangePassword $true `
            -Description "OOBE PPKG domain-join only. Delegated on $OU. No interactive logon. See Bitlocker-EntraBackup-Utility RUNBOOK." `
            -Path $AccountOU
        Write-Log "[OK] Created $upn in $AccountOU" -Color Green
        Write-Log "MUTATION: New-ADUser $AccountName in $AccountOU by $env:USERDOMAIN\$env:USERNAME"
        $user = Get-ADUser -Identity $AccountName -Properties PasswordNeverExpires, CannotChangePassword, Description, Enabled
    }
}
else {
    # Confirm/repair location of the existing account
    $parentDn = ($user.DistinguishedName -split ',', 2)[1]
    if ($parentDn -eq $AccountOU) {
        Write-Log "[OK] Location = $AccountOU" -Color Green
    }
    elseif ($VerifyOnly) {
        Write-Log "[!!] Account is in '$parentDn', expected '$AccountOU'" -Color Red
        $issues.Add("$AccountName in wrong OU")
    }
    elseif ($accountOuObj) {
        Move-ADObject -Identity $user.DistinguishedName -TargetPath $AccountOU
        Write-Log "[OK] Location: moved from '$parentDn' -> '$AccountOU'" -Color Green
        Write-Log "MUTATION: Move-ADObject $AccountName to $AccountOU by $env:USERDOMAIN\$env:USERNAME"
        $user = Get-ADUser -Identity $AccountName -Properties PasswordNeverExpires, CannotChangePassword, Description, Enabled
    }
    else {
        Write-Log "[!!] Account in '$parentDn' and target account OU is missing - cannot move." -Color Red
        $issues.Add("$AccountName in wrong OU (target OU missing)")
    }

    # Confirm/repair settings on the existing account
    $settings = @(
        @{ Name = 'Enabled';               Want = $true; Have = $user.Enabled;               Fix = { Enable-ADAccount -Identity $AccountName } }
        @{ Name = 'PasswordNeverExpires';  Want = $true; Have = $user.PasswordNeverExpires;  Fix = { Set-ADUser -Identity $AccountName -PasswordNeverExpires $true } }
        @{ Name = 'CannotChangePassword';  Want = $true; Have = $user.CannotChangePassword;  Fix = { Set-ADUser -Identity $AccountName -CannotChangePassword $true } }
        @{ Name = 'UserPrincipalName';     Want = $upn;  Have = $user.UserPrincipalName;     Fix = { Set-ADUser -Identity $AccountName -UserPrincipalName $upn } }
    )
    foreach ($s in $settings) {
        if ($s.Have -eq $s.Want) {
            Write-Log "[OK] $($s.Name) = $($s.Have)" -Color Green
        }
        elseif ($VerifyOnly) {
            Write-Log "[!!] $($s.Name) is '$($s.Have)', expected '$($s.Want)'" -Color Red
            $issues.Add("$AccountName $($s.Name) wrong")
        }
        else {
            & $s.Fix
            Write-Log "[OK] $($s.Name): corrected '$($s.Have)' -> '$($s.Want)'" -Color Green
            Write-Log "MUTATION: Set $($s.Name) on $AccountName by $env:USERDOMAIN\$env:USERNAME"
        }
    }

    if ($ResetPassword -and -not $VerifyOnly) {
        if (-not $AccountPassword) { $AccountPassword = Read-Host -AsSecureString "New password for $upn" }
        Set-ADAccountPassword -Identity $AccountName -Reset -NewPassword $AccountPassword
        Write-Log "[OK] Password reset - REBUILD THE PPKG NOW (runbook Part B) or field sticks stop joining." -Color Yellow
        Write-Log "MUTATION: password reset on $AccountName by $env:USERDOMAIN\$env:USERNAME"
    }
}

# --- Step 2: target OU ---
Write-Log "`n=== Step 2: target OU ===" -Color Cyan
$ouObj = $null
try {
    $ouObj = Get-ADOrganizationalUnit -Identity $OU
    Write-Log "[OK] OU exists: $($ouObj.DistinguishedName)" -Color Green
}
catch {
    Write-Log "[!!] OU not found: $OU" -Color Red
    $issues.Add("OU missing: $OU")

    # Help the operator find the right DN for a rerun
    Write-Log "Candidate OUs (pass the right one via -OU '<DN>'):" -Color Yellow
    $candidates = Get-ADOrganizationalUnit -Filter "Name -like '*workstation*' -or Name -like '*computer*' -or Name -like '*laptop*' -or Name -like '*desktop*'" |
        Select-Object -ExpandProperty DistinguishedName
    if (-not $candidates) {
        # Fall back to the OUs under GI Partners
        $candidates = Get-ADOrganizationalUnit -SearchBase 'OU=GI Partners,DC=pe,DC=gipartners,DC=com' -SearchScope OneLevel -Filter * -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty DistinguishedName
    }
    foreach ($c in $candidates) { Write-Log "  $c" -Color Yellow }
}

# --- Step 3: delegation ACEs ---
Write-Log "`n=== Step 3: delegation on OU ===" -Color Cyan

if ($user -and $ouObj) {
    # Well-known schema/rights GUIDs
    $computerClass = [guid]'bf967a86-0de6-11d0-a285-00aa003049e2'
    $resetPassword = [guid]'00299570-246d-11d0-a768-00aa006e0529'
    $attrGuids = @{
        'pwdLastSet'           = [guid]'bf967a0a-0de6-11d0-a285-00aa003049e2'
        'dNSHostName'          = [guid]'72e39547-7b18-11d1-adef-00c04fd8d5cd'
        'servicePrincipalName' = [guid]'f3a64788-5306-11d1-a9c5-0000f80367c1'
        'sAMAccountName'       = [guid]'3e0abfd0-126a-11d0-a060-00aa006c33ed'
        'userAccountControl'   = [guid]'bf967a68-0de6-11d0-a285-00aa003049e2'
    }

    $sid = [System.Security.Principal.SecurityIdentifier]$user.SID

    # Expected ACE list: name, rights, objectType, inheritance, inheritedObjectType
    $wanted = [System.Collections.Generic.List[object]]::new()
    $wanted.Add(@{ Name = 'Create computer objects (OU and below)'
                   Rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                       $sid, 'CreateChild', 'Allow', $computerClass, 'All') })
    $wanted.Add(@{ Name = 'Reset password (descendant computers)'
                   Rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                       $sid, 'ExtendedRight', 'Allow', $resetPassword, 'Descendents', $computerClass) })
    foreach ($attr in $attrGuids.Keys) {
        $wanted.Add(@{ Name = "Write $attr (descendant computers)"
                       Rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                           $sid, 'WriteProperty', 'Allow', $attrGuids[$attr], 'Descendents', $computerClass) })
    }
    foreach ($attr in @('dNSHostName', 'servicePrincipalName')) {
        $wanted.Add(@{ Name = "Validated write $attr (descendant computers)"
                       Rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                           $sid, 'Self', 'Allow', $attrGuids[$attr], 'Descendents', $computerClass) })
    }

    $adPath = "AD:\$($ouObj.DistinguishedName)"
    $acl = Get-Acl -Path $adPath
    $existing = $acl.Access | Where-Object { $_.IdentityReference -eq "$netbios\$AccountName" }

    $missing = [System.Collections.Generic.List[object]]::new()
    foreach ($w in $wanted) {
        $match = $existing | Where-Object {
            $_.ActiveDirectoryRights.HasFlag($w.Rule.ActiveDirectoryRights) -and
            $_.ObjectType -eq $w.Rule.ObjectType -and
            $_.InheritedObjectType -eq $w.Rule.InheritedObjectType -and
            $_.AccessControlType -eq 'Allow'
        }
        if ($match) {
            Write-Log "[OK] ACE present: $($w.Name)" -Color Green
        }
        else {
            $missing.Add($w)
            if ($VerifyOnly) {
                Write-Log "[!!] ACE MISSING: $($w.Name)" -Color Red
                $issues.Add("ACE missing: $($w.Name)")
            }
        }
    }

    if ($missing.Count -gt 0 -and -not $VerifyOnly) {
        foreach ($m in $missing) { $acl.AddAccessRule($m.Rule) }
        Set-Acl -Path $adPath -AclObject $acl
        foreach ($m in $missing) {
            Write-Log "[OK] ACE added: $($m.Name)" -Color Green
            Write-Log "MUTATION: ACE '$($m.Name)' added to $OU by $env:USERDOMAIN\$env:USERNAME"
        }
    }
}
else {
    Write-Log "[!!] Skipping delegation - account or OU unavailable." -Color Red
    $issues.Add("Delegation skipped (missing account or OU)")
}

# --- Verdict ---
Write-Log "`n=== Verdict ===" -Color Cyan
if ($issues.Count -eq 0) {
    Write-Log "ALL CHECKS GREEN - $upn is provisioned and delegated on $OU" -Color Green
    Write-Log "Reminders (manual, one-time):" -Color Yellow
    Write-Log "  1. Add $netbios\$AccountName to the 'Deny log on locally / via RDP' GPO." -Color Yellow
    Write-Log "  2. Verify redircmp / Connect sync scope covers $OU (RUNBOOK A2)." -Color Yellow
    Write-Log "  3. Use $netbios\$AccountName + this password when building the PPKG (RUNBOOK B5)." -Color Yellow
    Write-Log "Log: $logFile"
    exit 0
}
else {
    $n = 0
    foreach ($i in $issues) { $n++; Write-Log "[$n] $i" -Color Red }
    Write-Log "Log: $logFile"
    exit 1
}
