::###############################################################################################################
::
::    Zer0lightning's Windows 10 Security Hardening using Attack Surface Reduction (ASR) 
::    Read the comments and uncomment or comment relevant sections to make best use of it. 
::    License: Free to use for personal use.
::    This is based largely based on Atlant Security's Hardening Script.
::    https://raw.githubusercontent.com/atlantsecurity/windows-hardening-scripts/main/Windows-10-Hardening-script.cmd
::
::###############################################################################################################
:: Credits and More info: https://github.com/atlantsecurity/
::                        https://gist.github.com/mackwage/08604751462126599d7e52f233490efe
::                        https://github.com/LOLBAS-Project/LOLBAS
::                        https://lolbas-project.github.io/
::                        https://github.com/Disassembler0/Win10-Initial-Setup-Script
::                        https://github.com/cryps1s/DARKSURGEON/tree/master/configuration/configuration-scripts
::                        https://gist.github.com/alirobe/7f3b34ad89a159e6daa1#file-reclaimwindows10-ps1-L71
::                        https://github.com/teusink/Home-Security-by-W10-Hardening
::                        https://gist.github.com/ricardojba/ecdfe30dadbdab6c514a530bc5d51ef6
::
::###############################################################################################################
::###############################################################################################################
:: INSTRUCTIONS
:: Find the "EDIT" lines and change them according to your requirements and organization. Some lines
:: are not appropriate for large companies using Active Directory infrastructure, others are fine for small organizations, 
:: others are fine for individual users. At the start of tricky lines, I've added guidelines. 
:: It is a good idea to create a System Restore point before you run the script - as there are more than 920 lines in it,
:: finding out which line broke your machine is going to be trickly. You can also run the script in sequences manually the 
:: first few times, reboot, test your software and connectivity, proceed with the next sequence - this helps with troubleshooting.
:: HOW TO RUN THE SCRIPT
:: The command below creates the restore point, you can do it manually, too. 
powershell.exe enable-computerrestore -drive c:\
powershell.exe vssadmin resize shadowstorage /on=c: /for=c: /maxsize=5000MB
:: checkpoint-computer -description "beforehardening"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v SystemRestorePointCreationFrequency /t REG_DWORD /d 20 /f
powershell.exe -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 'BeforeSecurityHardening' -RestorePointType 'MODIFY_SETTINGS'"
:: 1. In Settings, search for Restore, then choose Create a restore point, then in System Protection, make sure it is On and has at least 6% of the drive.  
:: Create a Restore point, name it "Prior Security Hardening" 
:: 2. Go to https://raw.githubusercontent.com/atlantsecurity/windows-hardening-scripts/main/Windows-10-Hardening-script.cmd and download the cmd script to Downloads. 
:: It will download it as .txt - go to View in folder options, enable file extensions, change the filename to .cmd.  
:: 3. Open Powershell as Administrator, then type cd ~, then type cd .\Downloads\, type ls, type cmd 
:: 4. Type "Windows-10-Hardening-script.cmd"
:: 5. If you experience problems and need to roll back, roll back using the system restore point you created. 
::###############################################################################################################
::###############################################################################################################
:: Windows Defender Device Guard - Exploit Guard Policies (Windows 10 Only)
:: Enable ASR rules in Win10 ExploitGuard (>= 1709) to mitigate Office malspam
:: Blocks Office childprocs, Office proc injection, Office win32 api calls & executable content creation
:: Note these only work when Defender is your primary AV
:: Sources:
:: https://www.darkoperator.com/blog/2017/11/11/windows-defender-exploit-guard-asr-rules-for-office
:: https://www.darkoperator.com/blog/2017/11/8/windows-defender-exploit-guard-asr-obfuscated-script-rule
:: https://www.darkoperator.com/blog/2017/11/6/windows-defender-exploit-guard-asr-vbscriptjs-rule
:: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-attack-surface-reduction
:: https://demo.wd.microsoft.com/Page/ASR2
:: https://www.powershellgallery.com/packages/WindowsDefender_InternalEvaluationSettings/1.2/Content/WindowsDefender_InternalEvaluationSettings.ps1
:: https://blog.ahasayen.com/attack-surface-reduction/
:: https://www.verboon.info/2020/10/deploying-defender-asr-block-persistence-through-wmi-event-subscription/
:: https://github.com/commial/experiments/tree/master/windows-defender/ASR
:: Test https://demo.wd.microsoft.com/Page/ASR2
:: https://gist.githubusercontent.com/infosecn1nja/24a733c5b3f0e5a8b6f0ca2cf75967e3/raw/a7783a291bdd0c610b902fcc1daa7b743ca4f989/ASR%2520Rules%2520Bypass.vba
:: https://blog.sevagas.com/IMG/pdf/bypass_windows_defender_attack_surface_reduction.pdf
:: https://www.powershellgallery.com/packages/WindowsDefender_InternalEvaluationSettings/1.43/Content/WindowsDefender_InternalEvaluationSettings.ps1
:: https://argonsys.com/microsoft-cloud/library/microsoft-endpoint-manager-create-audit-an-asr-policy/
:: ---------------------
::###############################################################################################################
:: ASR Rules Enabled (not according to order)
:: 				Block executable content from email client and webmail
:: 				Block all Office applications from creating child processes
:: 				Block Office applications from creating executable content
:: 				Block Office applications from injecting code into other processes
:: 				Block JavaScript or VBScript from launching downloaded executable content
:: 				Block execution of potentially obfuscated scripts
:: 				Block Win32 API calls from Office macros
:: 				Block executable files from running unless they meet a prevalence, age, or trusted list criterion
:: 				Use advanced protection against ransomware
:: 				Block credential stealing from the Windows local security authority subsystem (lsass.exe)
:: 				Block process creations originating from PSExec and WMI commands
:: 				Block untrusted and unsigned processes that run from USB
:: 				Block Office communication application from creating child processes
:: 				Block Adobe Reader from creating child processes
:: 				Block persistence through WMI event subscription
:: 				Block abuse of exploited vulnerable signed drivers
:: ---------------------
:: Stop some of the most common SMB based lateral movement techniques dead in their tracks
powershell.exe Set-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D -AttackSurfaceReductionRules_Actions Enabled
::
:: Block Office applications from creating child processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
::
:: Block Office applications from injecting code into other processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions enable
::
:: Block Win32 API calls from Office macro
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions enable
::
:: Block Office applications from creating executable content
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions enable
::
:: Block execution of potentially obfuscated scripts
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
::
:: Block executable content from email client and webmail
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block JavaScript or VBScript from launching downloaded executable content
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
::
:: Block executable files from running unless they meet a prevalence, age, or trusted list criteria
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled
::
:: Use advanced protection against ransomware
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block Win32 API calls from Office macro
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
::
:: Block credential stealing from the Windows local security authority subsystem (lsass.exe)
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block untrusted and unsigned processes that run from USB
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block Adobe Reader from creating child processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled
::
:: Block process creations originating from PSExec and WMI commands
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled
::
:: Block Office communication application from creating child processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block abuse of exploited vulnerable signed drivers
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 56A863A9-875E-4185-98A7-B882C64B5CE5 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block persistence through WMI event subscription
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled
:: If you want to check the rules enabled.
:: Download and run this https://github.com/directorcia/Office365/blob/master/win10-asr-get.ps1
:: End
