@ECHO OFF & SETLOCAL EnableDelayedExpansion
color 0a
CALL :SetOnce

SET long=false

TITLE WinEnum - Windows Auditer enumeration - Running ...

SET "AdminOrNot="
cd %UserProfile%

REM Set UTF8
chcp 65001 > nul 


rem #---------------------------------------------------------------------------------#
rem # Name         = WinChecker v2.0 - WinAuditer                                     #
rem # Author       = @raphaelthief                                                    #
rem # Product      = Colt45 Production                                                #
rem #---------------------------------------------------------------------------------#

:initEOF
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
CALL :ColorLine "  %E%33m#      %E%32mName         =    WinChecker v2.0 - WinAuditer                        %E%33m#
CALL :ColorLine "  %E%33m#      %E%32mAuthor       =    @raphaelthief                                       %E%33m#
CALL :ColorLine "  %E%33m#      %E%32mProduct      =    Colt45 Production                                   %E%33m#
CALL :ColorLine "  %E%33m#----------------------------------------------------------------------------#"
echo.

setlocal enabledelayedexpansion

REM 36m = BLUE
REM 33m = YELLOW
REM 32m = GREEN
REM 31m = RED

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
	SET "AdminOrNot=1"
	echo.
	echo.
	CALL :ColorLine "%E%33m--------------------%E%32m"
	CALL :ColorLine "Execution rights :%E%36m User%E%32m"
	echo | set /p="Execution date : "
	DATE /T
	echo | set /p="Execution time : "
	TIME /T
	CALL :ColorLine "%E%33m--------------------%E%32m"
	goto startX
)

:except
CALL :ColorLine "%E%31mThe script is not launched with admin rights, certain functions will be incorrectly executed  ..."
echo.
CALL :ColorLine "	%E%33m1 - %E%32mContinue"
CALL :ColorLine "	%E%33m2 - %E%32mRestart with admin rights"
CALL :ColorLine "	%E%33m3 - %E%32mShow references and help menu"
CALL :ColorLine "	%E%33m4 - %E%32mClose"
echo.
set /p choix=Select : 

if "%choix%"=="1" (
	echo.
	CALL :ColorLine "%E%33m--------------------%E%32m"
	CALL :ColorLine "Execution rights :%E%36m User%E%32m"
	echo | set /p="Execution date : "
	DATE /T
	echo | set /p="Execution time : "
	TIME /T
	CALL :ColorLine "%E%33m--------------------%E%32m"
	goto startX
) else if "%choix%"=="2" (
	powershell.exe -Command "Start-Process '%~dpnx0' -Verb RunAs"
	exit
) else if "%choix%"=="3" (
	cls
	goto :helptips
) else if "%choix%"=="4" (
	exit
) else (
	CALL :ColorLine "%E%31mInvalid choice, press any key to exit ..."
	PAUSE >NUL
	exit
)

REM ####################### Here we go
:startX
echo.

REM Go to main tree at first
cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd .. & cd ..

REM ####################### Users infos
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Users infos %E%32m"
CALL :ColorLine "%E%36m[+] Actual user infos %E%32m"
echo | set /p="Username : "
echo %username%
echo | set /p="User profile : "
echo %userprofile%
echo | set /p="Hostname : "
hostname
echo.

CALL :ColorLine "%E%36m[+] Active session %E%32m"
quser
echo.

CALL :ColorLine "%E%36m[+] Users accounts %E%32m"
net user
echo.

CALL :ColorLine "%E%36m[+] Local groups %E%32m"
net localgroup
echo.

CALL :ColorLine "%E%36m[+] Whoami %E%32m"
whoami /all


REM ####################### System infos
echo.
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] System infos %E%32m"
CALL :ColorLine "%E%36m[+] Basic infos %E%32m"
wmic os get Caption, Version, OSArchitecture
echo local disks : 
(wmic logicaldisk get caption 2>nul | more) || (fsutil fsinfo drives 2>nul)
echo.

CALL :ColorLine "%E%36m[+] Environnement %E%32m"
set
echo.

CALL :ColorLine "%E%36m[+] System global infos %E%32m"
systeminfo
echo.

CALL :ColorLine "%E%36m[+] Installed softwares %E%32m"
wmic product get Name, Version
echo.

CALL :ColorLine "%E%36m[+] Installed softwares from HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall %E%32m"
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr InstallLocation | findstr ":\\"
echo.

CALL :ColorLine "%E%36m[+] Installed softwares from HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall %E%32m"
reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ /s | findstr InstallLocation | findstr ":\\"



REM ####################### Network configuration
echo.
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Network configuration %E%32m"
CALL :ColorLine "%E%36m[+] Basic infos %E%32m"
ipconfig /all

echo.
CALL :ColorLine "%E%36m[+] All the shares currently configured on the computer %E%32m"
net share

echo.
CALL :ColorLine "%E%36m[+] Open ports %E%32m"
netstat -ano

echo.
CALL :ColorLine "%E%36m[+] Route configuration %E%32m"
route print

echo.
CALL :ColorLine "%E%36m[+] Current ARP %E%32m"
arp -a

echo.
CALL :ColorLine "%E%36m[+] Actives connections %E%32m"
net share

echo.
CALL :ColorLine "%E%36m[+] DNS resolver cache %E%32m"
ipconfig /displaydns

echo.
CALL :ColorLine "%E%36m[+] Windows DNS hosts file %E%32m"
IF EXIST "C:\WINDOWS\System32\drivers\etc\hosts" (
    ECHO C:\WINDOWS\System32\drivers\etc\hosts
) ELSE (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)




REM ####################### Credencial search
echo.
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Searching for potential credencial files %E%32m"
CALL :ColorLine "%E%36m[+] FileZilla config file %E%32m"
IF EXIST "%USERPROFILE%\AppData\Roaming\FileZilla\filezilla.xml" (
    ECHO %USERPROFILE%\AppData\Roaming\FileZilla\filezilla.xml
)

REM Configuration files
echo.
CALL :ColorLine "%E%36m[+] Configuration files %E%32m"
SET "found="
IF EXIST "%SystemDrive%\sysprep.inf" (
    ECHO %SystemDrive%\sysprep.inf
	SET "found=1"
)
IF EXIST "%SystemDrive%\sysprep\sysprep.xml" (
    ECHO %SystemDrive%\sysprep\sysprep.xml
	SET "found=1"
)
IF EXIST "%WINDIR%\Panther\Unattend\Unattended.xml" (
    ECHO %WINDIR%\Panther\Unattend\Unattended.xml
	SET "found=1"
)
IF EXIST "%WINDIR%\Panther\Unattended.xml" (
    ECHO %WINDIR%\Panther\Unattended.xml
	SET "found=1"
)
IF EXIST "%WINDIR%\system32\sysprep\Unattend.xml" (
    ECHO %WINDIR%\system32\sysprep\Unattend.xml
	SET "found=1"
)
IF EXIST "%WINDIR%\system32\sysprep\Panther\Unattend.xml" (
    ECHO %WINDIR%\system32\sysprep\Panther\Unattend.xml
	SET "found=1"
)
IF EXIST "%WINDIR%\Panther\Unattend\Unattended.xml" (
    ECHO %WINDIR%\Panther\Unattend\Unattended.xml
	SET "found=1"
)
IF EXIST "%WINDIR%\Panther\Unattend.xml" (
    ECHO %WINDIR%\Panther\Unattend.xml
	SET "found=1"
)
IF EXIST "%SystemDrive%\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT" (
    ECHO %SystemDrive%\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT
	SET "found=1"
)
IF EXIST "%WINDIR%\panther\setupinfo" (
    ECHO %WINDIR%\panther\setupinfo
	SET "found=1"
)
IF EXIST "%WINDIR%\panther\setupinfo.bak" (
    ECHO %WINDIR%\panther\setupinfo.bak
	SET "found=1"
)
IF EXIST "%SystemDrive%\unattend.xml" (
    ECHO %SystemDrive%\unattend.xml
	SET "found=1"
)
IF EXIST "%WINDIR%\system32\sysprep.inf" (
    ECHO %WINDIR%\system32\sysprep.inf
	SET "found=1"
)
IF EXIST "%WINDIR%\system32\sysprep\sysprep.xml" (
    ECHO %WINDIR%\system32\sysprep\sysprep.xml
	SET "found=1"
)
IF EXIST "%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\Config\web.config" (
    ECHO %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
	SET "found=1"
)
IF EXIST "%SystemDrive%\inetpub\wwwroot\web.config" (
    ECHO %SystemDrive%\inetpub\wwwroot\web.config
	SET "found=1"
)
IF EXIST "%ALLUSERSPROFILE%\Application Data\McAfee\Common Framework\SiteList.xml" (
    ECHO %ALLUSERSPROFILE%\Application Data\McAfee\Common Framework\SiteList.xml
	SET "found=1"
)


IF NOT DEFINED found (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)



REM Registry passwords storage
echo.
CALL :ColorLine "%E%36m[+] Registry passwords storage %E%32m"
SET "found="
IF EXIST "HKLM\SOFTWARE\RealVNC\WinVNC4" (
    ECHO HKLM\SOFTWARE\RealVNC\WinVNC4
	SET "found=1"
)
IF EXIST "HKCU\Software\SimonTatham\PuTTY\Sessions" (
    ECHO HKCU\Software\SimonTatham\PuTTY\Sessions
	SET "found=1"
)
IF EXIST "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" (
    ECHO HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon
	SET "found=1"
)
IF EXIST "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" (
    ECHO HKLM\SYSTEM\CurrentControlSet\Services\SNMP
	SET "found=1"
)
IF EXIST "HKCU\Software\TightVNC\Server" (
    ECHO HKCU\Software\TightVNC\Server
	SET "found=1"
)
IF EXIST "HKCU\Software\SimonTatham\PuTTY\Sessions" (
    ECHO HKCU\Software\SimonTatham\PuTTY\Sessions
	SET "found=1"
)
IF EXIST "HKCU\Software\OpenSSH\Agent\Keys" (
    ECHO HKCU\Software\OpenSSH\Agent\Keys
	SET "found=1"
)

IF NOT DEFINED found (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)

REM Group policy preferences Password
echo.
CALL :ColorLine "%E%36m[+] Group policy preferences password %E%32m"
SET "found="
cd "%SystemDrive%\Microsoft\Group Policy\history" 2>nul
IF NOT ERRORLEVEL 1 (
    FOR /R "%SystemDrive%\Microsoft\Group Policy\history" %%F IN (
        "Groups.xml"
        "Services.xml"
        "Scheduledtasks.xml"
        "DataSources.xml"
        "Printers.xml"
        "Drives.xml"
    ) DO (
        IF EXIST "%%F" (
            echo %%F
            SET "found=1"
        )
    )
)

cd "%windir%\..\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history" 2>nul
IF NOT ERRORLEVEL 1 (
    FOR /R "%windir%\..\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history" %%F IN (
        "Groups.xml"
        "Services.xml"
        "Scheduledtasks.xml"
        "DataSources.xml"
        "Printers.xml"
        "Drives.xml"
    ) DO (
        IF EXIST "%%F" (
            echo %%F
            SET "found=1"
        )
    )
)

IF NOT DEFINED found (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)


REM credencials files
echo.
CALL :ColorLine "%E%36m[+] Cloud credencials files %E%32m"
cd "%SystemDrive%\Users" 2>nul
SET "found="
IF NOT ERRORLEVEL 1 (
	FOR /R "%SystemDrive%\Users" %%F IN (
		"gcloud"
		"credentials.db"
		"legacy_credentials"
		"access_tokens.db"
		".azure"
		"accessTokens.json"
		"azureProfile.json"
	) DO (
		IF EXIST "%%F" (
			echo %%F
			SET "found=1"
		)
	)
)

IF NOT DEFINED found (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)


REM Microsoft credencials files
echo.
CALL :ColorLine "%E%36m[+] Microsoft credencials files %E%32m"
CALL :ColorLine "%E%33m- %E%36m%appdata%\Microsoft\Credentials\ %E%32m"
dir /b/a "%appdata%\Microsoft\Credentials\" 2>nul
IF ERRORLEVEL 1 (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)
echo.
CALL :ColorLine "%E%33m- %E%36m%localappdata%\Microsoft\Credentials\ %E%32m"
dir /b/a %localappdata%\Microsoft\Credentials\
IF ERRORLEVEL 1 (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)


echo.
CALL :ColorLine "%E%36m[+] Check appcmd.exe %E%32m"
SET "found="
IF EXIST %systemroot%\system32\inetsrv\appcmd.exe (
    ECHO %systemroot%\system32\inetsrv\appcmd.exe exists
	SET "found=1"
)
IF NOT DEFINED found (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)


REM DPAPI Master keys
echo.
SET "notfoud="
CALL :ColorLine "%E%36m[+] DPAPI master keys %E%32m"
powershell -command "Get-ChildItem %appdata%\Microsoft\Protect" 2>nul
IF ERRORLEVEL 1 (
    SET "notfoud=1"
)
powershell -command "Get-ChildItem %localappdata%\Microsoft\Protect" 2>nul
IF ERRORLEVEL 1 (
    SET "notfoud=1"
)

IF DEFINED found (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)

REM Password cache
echo.
CALL :ColorLine "%E%36m[+] Windows passwords cache %E%32m"
cmdkey /list

echo.
CALL :ColorLine "%E%36m[+] SAM access files %E%32m"
echo SAM registry file :
reg query "HKLM\SAM\SAM"
CALL :ColorLine "%E%36m---- %E%32m"
echo SAM winsows file :
icacls "C:\Windows\System32\config\SAM"



REM Wifi passwords
echo.
CALL :ColorLine "%E%36m[+] WiFi profiles %E%32m"
netsh wlan show profiles 2>nul
IF ERRORLEVEL 1 (
    CALL :ColorLine "%E%31mNot Found or no Wireless interface%E%32m"
	goto :nowireless
)


CALL :ColorLine "%E%36m==================== Details ====================%E%32m"
echo.

for /f "skip=9 tokens=1,2 delims=:" %%i in ('netsh wlan show profiles') do (
    set "profile=%%j"
    set "profile=!profile:~1!"  REM Supprimer l'espace au début
    echo "!profile!" | findstr /i /v "echo" > nul && (
        CALL :ColorLine "%E%31m--------------------%E%36m"
		echo !profile!
		CALL :ColorLine "%E%31m--------------------%E%32m"
        netsh wlan show profiles "!profile!" key=clear
    )
)

:nowireless

REM ####################### Get current clipboard
echo.
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Current Clipboard %E%32m"
powershell -command "Get-Clipboard" 2>nul

IF ERRORLEVEL 1 (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)


REM ####################### Active security 
echo.
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Active defenses %E%32m"
CALL :ColorLine "%E%36m[+] Active Endpoint Protection %E%32m"
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName,pathToSignedReportingExe 2>nul
IF ERRORLEVEL 1 (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)

echo.
CALL :ColorLine "%E%36m[+] Defender exclusions %E%32m"
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" 
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions" 
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\IpAddresses" 
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes" 
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\TemporaryPaths" 

echo.
CALL :ColorLine "%E%36m[+] Firewall state %E%32m"
netsh advfirewall show allprofiles

echo.
CALL :ColorLine "%E%36m[+] Firewall global settings %E%32m"
netsh advfirewall show global



REM ####################### Running process & services 
echo.
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Running process and services infos %E%32m"
CALL :ColorLine "%E%36m[+] All running process and services %E%32m"
TASKLIST /SVC /FO table


echo.
CALL :ColorLine "%E%36m[+] AUTORITE NT\Système running process and services %E%32m"
TASKLIST /SVC /FO table /FI "USERNAME eq AUTORITE NT\Système"


echo.
CALL :ColorLine "%E%36m[+] Potential admin running process and services %E%32m"
TASKLIST /SVC /FO table /FI "USERNAME eq N/A"


echo.
CALL :ColorLine "%E%36m[+] Folders permissions of current processes (F) (M) (W) (WDAC) %E%32m"
echo.
CALL :ColorLine "%E%36mInfos :"

echo (F) 		- 	Full control
echo (M) 		- 	Modify
echo (RX) 		- 	Read and Execute
echo (R) 		- 	Read
echo (W) 		- 	Write
echo (D) 		- 	Delete
echo (WD) 		- 	Write Data
echo (AD) 		- 	Append Data
echo (REA) 		- 	Read Extended Attributes
echo (WEA) 		- 	Write Extended Attributes
echo (X) 		- 	Execute
echo (DC) 		- 	Delete Child
echo (RC) 		- 	Read/Execute
echo (WDAC)		- 	Write Data/Add File
echo (WO) 		- 	Write Owner
echo (S) 		- 	Synchronize
echo (CI) 		- 	Container Inherit
echo (OI) 		- 	Object Inherit
echo (IO) 		- 	Inherit Only
echo (NP) 		- 	No Access
echo (I) 		- 	Integrity
echo.
CALL :ColorLine "%E%32m"

for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('ECHO.%%x') do (
	CALL :ColorLine "%E%33mCurrent process :%E%36m %%x %E%32m" && icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) (WDAC) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && CALL :ColorLine "%E%36m----%E%32m"
)



REM ####################### Missconfigurations 
echo.
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Bad configurations %E%32m"
CALL :ColorLine "%E%36m[+] Unquoted paths %E%32m"

powershell.exe -Command "Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode | select Name,DisplayName,StartMode,PathName | Where-Object {$_.PathName -notlike 'C:\Windows\*' -and $_.PathName -notlike '\"*'}"

IF ERRORLEVEL 1 (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)

echo.
CALL :ColorLine "%E%36m[+] AlwaysInstallElevated %E%32m"
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul
IF ERRORLEVEL 1 (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)


REM ####################### Check somme config regedit key 
echo.
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Check regedit key config %E%32m"
CALL :ColorLine "%E%36m[+] User actions, security events, or system changes %E%32m"
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit 2>nul
IF %errorlevel% NEQ 0 (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)

echo.
CALL :ColorLine "%E%36m[+] Configuration settings related to event log forwarding %E%32m"
REG QUERY HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager 2>nul
IF %errorlevel% NEQ 0 (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)

echo.
CALL :ColorLine "%E%36m[+] Local Administrator Password Solution (LAPS) %E%32m"
REG QUERY "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled 2>nul
IF %errorlevel% NEQ 0 (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)

echo.
CALL :ColorLine "%E%36m[+] LSA protection %E%32m"
REG QUERY "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v RunAsPPL 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags 2>nul
IF %errorlevel% NEQ 0 (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)

echo.
CALL :ColorLine "%E%36m[+] WDigest authentication protocol %E%32m"
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential 2>nul
IF %errorlevel% NEQ 0 (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)



REM ####################### Startup stuffs 
echo.
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Startup files %E%32m"
CALL :ColorLine "%E%36m[+] Startup registry path %E%32m"
powershell -command "Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl" 2>nul

echo.
CALL :ColorLine "%E%36m[+] Schelduled tasks %E%32m"
schtasks /query /fo LIST | findstr /v /i "disable deshab"




echo.
CALL :ColorLine "%E%36m[+] Startup folders with files %E%32m"

IF EXIST "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" (
    for /f %%i in ('dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2^>nul') do (
        set "result=%%i"
    )
    IF "!result!"=="" (
        goto :n1
    ) ELSE (
        echo C:\Documents and Settings\All Users\Start Menu\Programs\Startup\!result!
    )
)

:n1

IF EXIST "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" (
    for /f %%i in ('dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2^>nul') do (
        set "result1=%%i"
    )
    IF "!result1!"=="" (
        goto :n2
    ) ELSE (
        echo C:\Documents and Settings\%username%\Start Menu\Programs\Startup\!result1!
    )
)

:n2

IF EXIST "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" (
    for /f %%i in ('dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2^>nul') do (
        set "result2=%%i"
    )
    IF "!result2!"=="" (
        goto :n3
    ) ELSE (
        echo %programdata%\Microsoft\Windows\Start Menu\Programs\Startup\!result2!
    )
)

:n3

IF EXIST "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" (
    for /f %%i in ('dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2^>nul') do (
        set "result3=%%i"
    )
    IF "!result3!"=="" (
        goto :n4
    ) ELSE (
        echo %appdata%\Microsoft\Windows\Start Menu\Programs\Startup\!result3!
    )
)

:n4

echo.
CALL :ColorLine "%E%36m[+] Startup folders permissions %E%32m"
icacls "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul && CALL :ColorLine "%E%36m----%E%32m" 
icacls "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul && CALL :ColorLine "%E%36m----%E%32m"
icacls "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul && CALL :ColorLine "%E%36m----%E%32m"
icacls "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul && CALL :ColorLine "%E%36m----%E%32m"


REM ####################### UAC settings
echo.
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] UAC settings %E%32m"
CALL :ColorLine "%E%36m[+] UAC status %E%32m"
reg QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA 2>nul
IF ERRORLEVEL 1 (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)

echo.
CALL :ColorLine "%E%36m[+] Try to elevate throught elevated eventvwr process %E%32m"
where /r C:\\windows eventvwr.exe



REM ####################### Powershell infos
echo.
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Powershell infos %E%32m"
CALL :ColorLine "%E%36m[+] Powershell V2 Version %E%32m"
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine /v PowerShellVersion 2>nul
IF ERRORLEVEL 1 (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)

echo.
CALL :ColorLine "%E%36m[+] Powershell V5 Version %E%32m"
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine /v PowerShellVersion 2>nul
IF ERRORLEVEL 1 (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)

echo.
CALL :ColorLine "%E%36m[+] Transcriptions %E%32m"
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription 2>nul
IF ERRORLEVEL 1 (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)

echo.
CALL :ColorLine "%E%36m[+] Module logging %E%32m"
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging 2>nul
IF ERRORLEVEL 1 (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)

echo.
CALL :ColorLine "%E%36m[+] Script logging %E%32m"
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging 2>nul
IF ERRORLEVEL 1 (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)

echo.
CALL :ColorLine "%E%36m[+] Powershell commands history %E%32m"
IF EXIST "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" (
    ECHO %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
) ELSE (
    CALL :ColorLine "%E%31mNot Found%E%32m"
)







REM ####################### Chromium enum
echo.
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Chromium interesting files %E%32m"
set "roaming=%APPDATA%"
set "local=%LOCALAPPDATA%"


for %%A in (
    "%roaming%\Opera Software"
    "%local%\Microsoft\Edge"
    "%local%\Google\Chrome"
    "%local%\Google\Chrome SxS"
    "%local%\Google\Chrome Beta"
    "%local%\Google\Chrome Dev"
    "%local%\Google\Chrome Unstable"
    "%local%\Google\Chrome Canary"
    "%local%\BraveSoftware\Brave-Browser"
    "%local%\Vivaldi"
    "%local%\Yandex\YandexBrowser"
    "%local%\Yandex\YandexBrowserCanary"
    "%local%\Yandex\YandexBrowserDeveloper"
    "%local%\Yandex\YandexBrowserBeta"
    "%local%\Yandex\YandexBrowserTech"
    "%local%\Yandex\YandexBrowserSxS"
) do (
    if exist "%%~A" (
		echo.
		CALL :ColorLine "%E%36m[+] Browser dir :  %%~A %E%32m"
		set "search_dir=%%~A"
		set "last_dir=%%~A"  
		call :maFonction
    )
)


if defined last_dir (
    goto :nextit
)

:maFonction

		for /r "%search_dir%" %%a in (*) do (
			if "%%~nxa"=="Local State" (
				CALL :ColorLine "%E%36mLocal State :%E%32m %%a"
			)
		)      
		CALL :ColorLine "%E%36m----%E%32m"

		for /r "%search_dir%" %%a in (*) do (
			if "%%~nxa"=="Web Data" (
				CALL :ColorLine "%E%36mWeb Data :%E%32m %%a"
			)
		)      
		CALL :ColorLine "%E%36m----%E%32m"

		for /r "%search_dir%" %%a in (*) do (
			if "%%~nxa"=="Cookies" (
				CALL :ColorLine "%E%36mCookies :%E%32m %%a"
			)
		)    
		CALL :ColorLine "%E%36m----%E%32m"
			

		for /r "%search_dir%" %%a in (*) do (
			if "%%~nxa"=="History" (
				CALL :ColorLine "%E%36mHistory :%E%32m %%a"
			)
		)    
		CALL :ColorLine "%E%36m----%E%32m"

		for /r "%search_dir%" %%a in (*) do (
			if "%%~nxa"=="Login Data" (
				CALL :ColorLine "%E%36mLogin Data :%E%32m %%a"
			)
		)   
		CALL :ColorLine "%E%36m----%E%32m"
goto :eof
:nextit



REM ####################### Missing updates Check
echo.
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Checking missing updates %E%32m"

set "ClientApplicationID=WES-NG validation script"
for /f "tokens=* delims=" %%a in ('powershell -Command "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0 and Type=''Software'' and IsHidden=0').Updates | ForEach-Object { 'KB' + $_.KBArticleIDs[0] + ': ' + $_.Title }"') do (
	CALL :ColorLine "%E%36m[+]%E%32m %%a"
)
for /f "tokens=* delims=" %%a in ('powershell -Command "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0 and Type=''Software'' and IsHidden=0').Updates.Count"') do (
    set "UpdateCount=%%a"
)
if "%UpdateCount%"=="0" (
	CALL :ColorLine "%E%31mNot Found%E%32m"
)



REM ####################### CVE Check
echo.
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Checking potential CVE with Wesng (https://github.com/bitsadmin/wesng) %E%32m"

REM Check if Python is installed
CALL :ColorLine "%E%36m[+] Check dependencies ... %E%32m"
CALL :ColorLine "%E%33m- %E%36mChecking if python is installed%E%32m"

python --version >nul 2>&1
IF ERRORLEVEL 1 (
	CALL :ColorLine "%E%31mNot installed%E%32m"
	echo.
	
	IF NOT DEFINED AdminOrNot (
		CALL :ColorLine "%E%31mYou are not admin, follow these instructions :%E%32m"
		echo - Install Python from the microsoft store - no admin rights needed sometimes
		echo.
		echo Press any key to open microsoft store
		PAUSE >NUL
		start ms-windows-store://pdp/?productid=9PJPW5LDXLZ5
		echo.
		echo - Install python then continue or just ignore
		echo.
		echo Press any key to continue
		PAUSE >NUL	
	) else (
		winget install -e --id Python.Python.3.11
	)
	
) else (
python --version
echo.
)

REM Go to local script dir
cd %~dp0

REM Check if wesng is already downloaded
CALL :ColorLine "%E%33m- %E%36mChecking if wesng is present%E%32m"
set WESNG_DIR=%~dp0wesng-master

IF NOT EXIST "%WESNG_DIR%" (
	CALL :ColorLine "%E%31mNot present%E%32m"
	echo.
	CALL :ColorLine "%E%33m- %E%36mDownloading wesng%E%32m"
	curl -L -o WESNG.zip https://github.com/bitsadmin/wesng/archive/refs/heads/master.zip
    IF ERRORLEVEL 1 (
        CALL :ColorLine "%E%31mFailed downloading wesng%E%32m"
        goto :endit
    )	
	echo.
	CALL :ColorLine "%E%33m- %E%36mExtracting file%E%32m"
	tar -xf WESNG.zip
    IF ERRORLEVEL 1 (
        CALL :ColorLine "%E%31mFailed extracting wesng%E%32m"
        goto :endit
    )	
)


echo.
CALL :ColorLine "%E%36m[+] Launching wesng ... %E%32m"
REM Navigate to the wesng directory
cd "%WESNG_DIR%"

REM Update the vulnerability database
CALL :ColorLine "%E%33m- %E%36mUpdating wesng database ... %E%32m"
python wes.py --update
echo.
IF ERRORLEVEL 1 (
	echo.
	CALL :ColorLine "%E%31mFailed to update wesng database%E%32m"
	echo.
)

REM Collect system information
CALL :ColorLine "%E%33m- %E%36mCollecting system information ... %E%32m"
systeminfo > systeminfo.txt
IF ERRORLEVEL 1 (
	echo.
	CALL :ColorLine "%E%31mFailed to collect system information%E%32m"
	goto :endit
)
echo Ok
echo.

REM Run Wesng with the collected system information
CALL :ColorLine "%E%33m- %E%36mRunning wesng analysis ... %E%32m"
python wes.py -c systeminfo.txt 
IF ERRORLEVEL 1 (
	echo.
	CALL :ColorLine "%E%31mwesng analysis failed%E%32m"
    goto :endit
)

goto :endit




:endit
REM ####################### END
echo.
echo.
CALL :ColorLine "%E%31m#################### %E%33mScan complete %E%31m####################"
TITLE WinEnum - Windows Auditer enumeration - IDLE
echo.
CALL :ColorLine "%E%32mPress any key to exit"
PAUSE >NUL
exit

REM ####################### Form Settings
:SetOnce
SET "E=0x1B["
SET "PercentageTrack=0"
EXIT /B

:ColorLine
SET "CurrentLine=%~1"
FOR /F "delims=" %%A IN ('FORFILES.EXE /P %~dp0 /M %~nx0 /C "CMD /C ECHO.!CurrentLine!"') DO ECHO.%%A
EXIT /B



REM ####################### References and help menu
:helptips

echo                      ____ ^_____ ^_____ __  __   _ 
echo                     ^|  _ ^\_   _^|  ___^|  \/  ^| ^| ^|
echo                     ^| ^|_) ^|^| ^| ^| ^|_^  ^| ^|\/^| ^| ^| ^|
echo                     ^|  _ ^< ^| ^| ^|  _^| ^| ^|  ^| ^| ^|_^|
echo                     ^|_^| ^\_\^|_^| ^|_^|   ^|_^|  ^|_^| ^(_^)
CALL :ColorLine "                    %E%36m__________%E%37m__________%E%31m_________"

echo.
echo.
echo.
CALL :ColorLine "%E%31m_________________________________"
CALL :ColorLine "%E%33m[i] raphaelthief%E%32m"
CALL :ColorLine "%E%36m[+] Github%E%32m"
echo	    https://github.com/raphaelthief
CALL :ColorLine "%E%36m[+] Medium%E%32m"
echo	    https://medium.com/@raphaelthief
CALL :ColorLine "%E%36m[+] Startme%E%32m"
echo	    https://start.me/p/kvvGLO/cti-osint



echo.
CALL :ColorLine "%E%31m_________________________________"
CALL :ColorLine "%E%33m[i] Interesting cheat sheet%E%32m"
CALL :ColorLine "%E%36m[+] Privesc%E%32m"
echo	    https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
echo	    https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/
echo	    https://www.thehacker.recipes/infra/privilege-escalation/windows
echo	    https://exploit-notes.hdks.org/exploit/windows/privilege-escalation/
CALL :ColorLine "%E%36m[+] Credencials%E%32m"
echo	    https://en.hackndo.com/remote-lsass-dump-passwords/
echo	    https://github.com/raphaelthief/WebBrowserVuln


echo.
CALL :ColorLine "%E%31m_________________________________"
CALL :ColorLine "%E%33m[i] Exploits DB%E%32m"
CALL :ColorLine "%E%36m[+] Offsec%E%32m"
echo	    https://www.exploit-db.com/
CALL :ColorLine "%E%36m[+] Search engines%E%32m"
echo	    https://exploits.shodan.io/welcome
echo	    https://sploitus.com/



echo.
CALL :ColorLine "%E%31m_________________________________"
CALL :ColorLine "%E%33m[i] Tools%E%32m"
CALL :ColorLine "%E%36m[+] Wesng - CVE enum%E%32m"
echo	    https://github.com/bitsadmin/wesng
CALL :ColorLine "%E%36m[+] Microsoft tools%E%32m"
echo	    https://learn.microsoft.com/fr-fr/sysinternals/downloads/accesschk
echo	    https://learn.microsoft.com/fr-fr/sysinternals/downloads/procdump
echo	    https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite
CALL :ColorLine "%E%36m[+] Mimikatz - Passwords dump%E%32m"
echo	    https://blog.gentilkiwi.com/mimikatz
CALL :ColorLine "%E%36m[+] Invoke-TheHash - Passwords dump%E%32m"
echo	    https://github.com/Kevin-Robertson/Invoke-TheHash
CALL :ColorLine "%E%36m[+] NavKiller - Webbrowser decrypt%E%32m"
echo	    https://github.com/raphaelthief/NavKiller

echo.
echo.
CALL :ColorLine "%E%32mPress any key to go back to main menu ..."
PAUSE >NUL
cls
goto :initEOF
