@ECHO OFF & SETLOCAL EnableDelayedExpansion
color 0a
CALL :SetOnce

SET long=false

TITLE WinChecker - WindowsEnum - Running ...

rem #---------------------------------------------------------------------------------#
rem # Name         = WinChecker v1.0                                                  #
rem # Author       = @raphaelthief                                                    #
rem # Product      = Colt45 Production                                                #
rem #---------------------------------------------------------------------------------#

CALL :ColorLine "                                   %E%31m*####*/@@/ "                                  
CALL :ColorLine "                               %E%31m#@@#####(,,(#@@@@                           "     
CALL :ColorLine "                            %E%31m#@@@#(/**,/,  .,#%#@@@@                           "  
CALL :ColorLine "                          %E%31m#@@@@##/*,.,,....,,*######@/                        "  
CALL :ColorLine "                        %E%31m/@@@####((/*/*,,,*,,*/(##((###@#                       " 
CALL :ColorLine "                       %E%31m@@@##(/***/((****,*,,,*,*/(//*/##@*                     " 
CALL :ColorLine "                     %E%31m,@@##(*((/,*,.,.           ..**,,,*/#@#                   " 
CALL :ColorLine "                    %E%31m@@#(#*      ...                ...,,,,*(#@(                " 
CALL :ColorLine "                 %E%31m(@@/*,                                      .,%@              " 
CALL :ColorLine "               %E%31m,@*/.              %E%36m,%E%36m*************                %E%31m*#             " 
CALL :ColorLine "              %E%31m#/.               %E%36m,%E%36m******  ,********,              %E%31m./            " 
CALL :ColorLine "             %E%31m(,               %E%36m.********  ,********,               %E%31m(            "
CALL :ColorLine "             %E%31m(                 %E%36m*******,  .********,              %E%31m/             "
CALL :ColorLine "             %E%31m(                   %E%36m.,,.    *********              %E%31m/              "
CALL :ColorLine "              %E%31m#                         %E%36m********              %E%31m*                "
CALL :ColorLine "               %E%31m*.                     %E%36m.*****,                %E%31m/                 "
CALL :ColorLine "                 %E%31m/                    %E%36m****                 %E%31m/                   "
CALL :ColorLine "                 %E%31m(@/                  %E%36m***                 %E%31m##@#                " 
CALL :ColorLine "             %E%31m#(((**,*.                 %E%36m..               %E%31m,((*(#/#@@.          "  
CALL :ColorLine "        %E%31m,###(/**,,,.../             %E%36m.******            %E%31m(/((#**/((#(##/       "  
CALL :ColorLine "      %E%31m,@##/**,,,....../             %E%36m********          %E%31m,  ,/((,./(/*(,**#.     " 
CALL :ColorLine "     %E%31m@##((/,*,    ,..   .             %E%36m.,.           %E%31m*,      (,.*     ,# (,     "
CALL :ColorLine "   %E%31m@##(*///,..    ....   .                           *,      (,.*     ,# (,    "
CALL :ColorLine "  %E%31m(#/*.,../,.      ..    ,.                      ,.  *,.      ./(     ./  @*   "
CALL :ColorLine "  %E%31m##*. .  .*        .    ,.                     ..   ,*         (     ,.  (#   "
CALL :ColorLine " %E%31m/#(   .   .             ,..                    .    ,(         .  .  .   ,,#  "
CALL :ColorLine "  %E%31m./*        .            ,                           *#          .        , .  "
CALL :ColorLine "   %E%31m.,                     .                           //           .      .  "

echo.
CALL :ColorLine "  %E%33m#----------------------------------------------------------------------------#"
CALL :ColorLine "  %E%33m#      %E%32mName         =    WinChecker - Global Enumeration  v1.0               %E%33m#
CALL :ColorLine "  %E%33m#      %E%32mAuthor       =    @raphaelthief                                       %E%33m#
CALL :ColorLine "  %E%33m#      %E%32mProduct      =    Colt45 Production                                   %E%33m#
CALL :ColorLine "  %E%33m#----------------------------------------------------------------------------#"
echo.
CALL :ColorLine "  %E%32mThis tool may generate certain DNS issues on the machine on which it is run. If you encounter such an issue, please restart the computer and everything will return to normal."
echo.

setlocal enabledelayedexpansion


REM ####################### Check admin rights for execution
net session >nul 2>&1
if %errorlevel% neq 0 (
    set ADMIN_LEVEL=0
	CALL :except
) else (
    CALL :ColorLine "%E%33mAdmin rights enabled, ready to use"
    CALL :ColorLine "%E%32mPress any key to continue ..."
    PAUSE >NUL
    echo.
    set ADMIN_LEVEL=1
	goto startX
)


:except
CALL :ColorLine "%E%31mThe script is not launched with admin rights, certain functions will be incorrectly executed  ..."
echo.
CALL :ColorLine "	%E%33m1 - %E%32mContinue"
CALL :ColorLine "	%E%33m2 - %E%32mRestart with admin rights"
CALL :ColorLine "	%E%33m3 - %E%32mClose"
echo.
set /p choix=Select : 

if "%choix%"=="1" (
	goto startX
) else if "%choix%"=="2" (
	powershell.exe -Command "Start-Process '%~dpnx0' -Verb RunAs"

	exit
) else if "%choix%"=="3" (
	exit
) else (
	CALL :ColorLine "%E%31mInvalid choice, press any key to exit ..."
	PAUSE >NUL
	exit
)


REM ####################### Here we go
:startX
REM Go to main tree at first
cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. 


REM ####################### User infos
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] User infos : %E%32m"
CALL :ColorLine "%E%33m[+] %E%36mHostname : %E%32m"
echo.
hostname 2>NUL

echo.
CALL :ColorLine "%E%33m[+] %E%36mUsername : %E%32m"
echo.
echo %username% 2>NUL
whoami 2>NUL
echo %userprofile% 2>NUL

REM ####################### Get all account users
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Machine Users %E%32m"
net users

REM ####################### Local groups
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] GROUPS %E%32m"
net localgroup


REM ####################### Current user logged
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Current logged users %E%32m"
echo.
quser

REM ####################### Settings privileges account with the actual rights
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] User Privileges %E%32m"
whoami /priv

REM ####################### Get OS version, architecture and name
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] OS Version %E%32m"
echo.
wmic os get Caption, Version, OSArchitecture

REM ####################### Networks cards, updates, proc, region etc ...
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] System Basic infos %E%32m"
CALL :ColorLine "%E%33m[+] %E%36mGlobal info's %E%32m"
systeminfo
echo.

CALL :ColorLine "%E%33m[+] %E%36mPhysical memory %E%32m"
echo.
wmic COMPUTERSYSTEM get TotalPhysicalMemory,caption

REM ####################### Get mounted disks
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Mounted disks %E%32m"
echo.
(wmic logicaldisk get caption 2>nul | more) || (fsutil fsinfo drives 2>nul)

REM ####################### Get machine environnement (Temp location, windir, userdomain, etc ...)
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Environment %E%32m"
echo.
set

REM ####################### Get installed software with versions. If there are many of thems it takes time
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Installed Softwares %E%32m"
echo.
wmic product get Name, Version

REM ####################### Installed softwares from reg keys get location of each
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Installed Softwares locations %E%32m"
CALL :ColorLine "%E%33m[+] %E%36mHKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall %E%32m"
echo.
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr InstallLocation | findstr ":\\"
echo.
CALL :ColorLine "%E%33m[+] %E%36mHKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ %E%32m"
echo.
reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ /s | findstr InstallLocation | findstr ":\\"


REM ####################### Ipconfig /all
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Nework Configuration %E%32m"
ipconfig /all

REM ####################### List all the shares currently configured on the computer
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Nework %E%32m"
net share

REM ####################### Display the IP routing table
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Route Configuration %E%32m"
echo.
route print

REM ####################### Display the current ARP 
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] ARP Cache %E%32m"
arp -a

REM ####################### Display network statistics, connections, and port information
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Active Connexions %E%32m"
netstat -ano




REM ####################### DNS Windows file
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Host DNS Windows file %E%32m"
echo.
dir C:\WINDOWS\System32\drivers\etc\hosts | findstr /v "^#" 2>nul

REM ####################### Display the contents of the DNS resolver cache
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] DNS resolver cache %E%32m"
ipconfig /displaydns


REM ####################### AV & co on system
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Present Anti-Virus on the system %E%32m"
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List | more 

REM ####################### Get all exclusions of Defender
CALL :ColorLine "%E%33m[+] %E%36mChecking for all defender exclusions ... %E%32m"
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" 
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions" 
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\IpAddresses" 
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes" 
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\TemporaryPaths" 

rem ####################### Firewall command update to news windows versions. Make changes if needed
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Firewall Settings %E%32m"
CALL :ColorLine "%E%33m[+] %E%36mAllprofiles state %E%32m"
netsh advfirewall show allprofiles state
echo.
CALL :ColorLine "%E%33m[+] %E%36mFirewall currentprofile %E%32m"
netsh advfirewall show currentprofile


REM ####################### Running services
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Running Services %E%32m"
echo.
net start


REM ####################### Process, PID, Services
REM ####################### https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#running-processes
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Running Processes with PID and Services %E%32m"
tasklist /SVC


REM ####################### Checking permissions from active processes and associated folders
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Running Processes with PID and Services %E%32m"
CALL :ColorLine "%E%33m[+] %E%36mVerifying file permissions for active processes %E%32m"
echo.
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('ECHO.%%x') do (
		icacls "%%z" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO.
	)
)

echo.
CALL :ColorLine "%E%33m[+] %E%36mVerifying directory permissions for active processes (DLL injection) %E%32m"
echo.
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('ECHO.%%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO.
)


REM ####################### Executable file permissions on services with non-system32 paths
REM ####################### https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Executable file permissions on services with non-system32 paths %E%32m"
echo.
for /f "tokens=2 delims='='" %%a in ('cmd.exe /c wmic service list full ^| findstr /i "pathname" ^|findstr /i /v "system32"') do (
    for /f eol^=^"^ delims^=^" %%b in ("%%a") do icacls "%%b" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos usuarios %username%" && echo.
)


REM ####################### Checks the permissions of each directory listed in the system PATH environment variable
REM ####################### https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dll-hijacking
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Checking the permissions of each directory listed in the system PATH environment variable %E%32m"
echo.
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )


REM ####################### Hijacking folder locations without quotes
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Folder locations without quotes %E%32m"
echo.
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """


REM ####################### Startup stuffs from regedit, startup folder & scheduled tasks
REM ####################### https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#run-at-startup
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Startup stuffs %E%32m"
CALL :ColorLine "%E%33m[+] %E%36mRegistry startup keys Run %E%32m"
echo.
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run 2>nul & reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>nul & reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run 2>nul & reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>nul
echo.

CALL :ColorLine "%E%33m[+] %E%36mWindows startup folder %E%32m"
echo.
icacls "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. & icacls "C:\Documents and Settings\All Users\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. & icacls "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. & icacls "C:\Documents and Settings\%username%\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.

CALL :ColorLine "%E%33m[+] %E%36mList of scheduled tasks %E%32m"
echo.
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab informa")


REM ####################### GPO AlwaysInstallElevated on registry 
REM ####################### https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#alwaysinstallelevated
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Check Windows installer .msi - AlwaysInstallElevated %E%32m"
echo.
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul


REM ####################### Security updates set with their versions
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Updates fix set on %E%32m"
echo.
wmic qfe get Caption,Description,FixComments,HotFixID,InstallDate,InstalledBy,InstalledOn,Name,ServicePackInEffect,Status


REM ####################### Checking user actions, security events, or system changes
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Checking user actions, security events, or system changes %E%32m"
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit 2>nul


REM ####################### Retrieve configuration settings related to event log forwarding
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Retrieve configuration settings related to event log forwarding %E%32m"
REG QUERY HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager 2>nul

REM ####################### Check whether the Local Administrator Password Solution (LAPS)
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Check whether the Local Administrator Password Solution (LAPS) %E%32m"
REG QUERY "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled 2>nul

REM ####################### Check LSA protection
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Check LSA protection %E%32m"
REG QUERY "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v RunAsPPL 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags 2>nul


REM ####################### WDigest authentication protocol is configured to store plaintext passwords in memory on the system
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Checking WDigest authentication protocol %E%32m"
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential 2>nul

REM ####################### Determine the number of cached logon credentials allowed on the system
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Number of cached logon credentials allowed on the system %E%32m"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CACHEDLOGONSCOUNT 2>nul

REM ####################### Determine whether User Account Control (UAC) is enabled or disabled on the system
REM ####################### https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#basic-uac-bypass-full-file-system-access
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] UAC status on the system %E%32m"
reg QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA 2>nul


REM ####################### Powershell stuff
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] PowerShell settings %E%32m"
CALL :ColorLine "%E%33m[+] %E%36mPowerShell v2 Version %E%32m"
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine /v PowerShellVersion 2>nul
echo.
CALL :ColorLine "%E%33m[+] %E%36mPowerShell v5 Version %E%32m"
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine /v PowerShellVersion 2>nul
echo.
CALL :ColorLine "%E%33m[+] %E%36mTranscriptions Settings %E%32m"
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription 2>nul
echo.
CALL :ColorLine "%E%33m[+] %E%36mModule logging settings %E%32m"
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging 2>nul
echo.
CALL :ColorLine "%E%33m[+] %E%36mScriptblog logging settings %E%32m"
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging 2>nul
echo.
CALL :ColorLine "%E%33m[+] %E%36mChecking PowerShell default transcript history %E%32m"
echo.
dir %SystemDrive%\transcripts\ 2>nul
echo.
CALL :ColorLine "%E%33m[+] %E%36mChecking PowerShell history file %E%32m"
echo.
dir "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" 2>nul




REM #####################################################################
REM #####################################################################
REM ####################### Too much accumulation I put it off
REM echo.
REM CALL :ColorLine "%E%31m--------------------"
REM CALL :ColorLine "%E%33m[i] Backup Files %E%32m"
REM dir /s *backup.*
REM #####################################################################
REM #####################################################################
REM #####################################################################




REM ####################### Potentially risky permissions are granted to specific users or groups
REM ####################### https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Checking any service registry that can be modificated %E%32m"
echo.
for /f %%a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv >nul 2>&1 & reg save %%a %temp%\reg.hiv >nul 2>&1 && reg restore %%a %temp%\reg.hiv >nul 2>&1 && ECHO.You can modify %%a


REM ####################### Check for the existence of various sysprep-related files and configuration files 
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Check for the existence of various sysprep-related files and configuration files %E%32m"
echo.
IF EXIST %WINDIR%\sysprep\sysprep.xml ECHO.%WINDIR%\sysprep\sysprep.xml exists. 
IF EXIST %WINDIR%\sysprep\sysprep.inf ECHO.%WINDIR%\sysprep\sysprep.inf exists. 
IF EXIST %WINDIR%\sysprep.inf ECHO.%WINDIR%\sysprep.inf exists. 
IF EXIST %WINDIR%\Panther\Unattended.xml ECHO.%WINDIR%\Panther\Unattended.xml exists. 
IF EXIST %WINDIR%\Panther\Unattend.xml ECHO.%WINDIR%\Panther\Unattend.xml exists. 
IF EXIST %WINDIR%\Panther\Unattend\Unattend.xml ECHO.%WINDIR%\Panther\Unattend\Unattend.xml exists. 
IF EXIST %WINDIR%\Panther\Unattend\Unattended.xml ECHO.%WINDIR%\Panther\Unattend\Unattended.xml exists.
IF EXIST %WINDIR%\System32\Sysprep\unattend.xml ECHO.%WINDIR%\System32\Sysprep\unattend.xml exists.
IF EXIST %WINDIR%\System32\Sysprep\unattended.xml ECHO.%WINDIR%\System32\Sysprep\unattended.xml exists.
IF EXIST %WINDIR%\..\unattend.txt ECHO.%WINDIR%\..\unattend.txt exists.
IF EXIST %WINDIR%\..\unattend.inf ECHO.%WINDIR%\..\unattend.inf exists. 


REM ####################### Checking for SiteList.xml
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Checking for SiteList.xml %E%32m"
echo.
cd %ProgramFiles% 2>nul
dir /s SiteList.xml 2>nul
cd %ProgramFiles(x86)% 2>nul
dir /s SiteList.xml 2>nul
cd "%windir%\..\Documents and Settings" 2>nul
dir /s SiteList.xml 2>nul
cd %windir%\..\Users 2>nul
dir /s SiteList.xml 2>nul
cd ..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\.. REM Go to main tree at first


REM ####################### AppCmd
REM ####################### https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#appcmd.exe
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Checking for AppCmd %E%32m"
echo.
IF EXIST %systemroot%\system32\inetsrv\appcmd.exe echo.%systemroot%\system32\inetsrv\appcmd.exe exists.

:testX
REM ####################### END
echo.
echo.
CALL :ColorLine "%E%31m#################### %E%33mScan complete %E%31m####################"
TITLE WinChecker - WindowsEnum - IDLE
PAUSE >NUL


REM ####################### Form Settings
:SetOnce
SET "E=0x1B["
SET "PercentageTrack=0"
EXIT /B

:ColorLine
SET "CurrentLine=%~1"
FOR /F "delims=" %%A IN ('FORFILES.EXE /P %~dp0 /M %~nx0 /C "CMD /C ECHO.!CurrentLine!"') DO ECHO.%%A
EXIT /B

