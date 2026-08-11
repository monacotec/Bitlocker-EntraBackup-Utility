@echo off
REM Runs during OOBE via provisioning package (ProvisioningCommands, device context).
REM Blocks Windows 11 24H2+ automatic device encryption so the drive stays cleartext
REM until the Intune BitLocker policy encrypts it (escrow-first, XTS-AES 256).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" /v PreventDeviceEncryption /t REG_DWORD /d 1 /f
exit /b 0
