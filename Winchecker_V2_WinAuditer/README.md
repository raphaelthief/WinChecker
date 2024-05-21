WinAuditer aims to scan any Windows environment for potential vulnerabilities related to misconfigurations that could lead to password extraction, privilege escalations, or installation backdoors. While creating this tool, I am not reinventing the wheel. However, I am bringing a different perspective to the execution of these tools through specific additions and a different presentation of the extracted results.

![WinAuditer](https://github.com/raphaelthief/WinChecker/blob/main/Pictures/Main2.JPG "WinAuditer")

## Disclaimer

I am not responsible for the use you will make of this tool. Its purpose is solely to be used by the cybersecurity community who wish to use tools other than those already provided in their own environment or with the permission of the owners of those environments.

## WinCAuditer Features

### Purposes

This tool aims to perform the main enumerations of misconfigurations that could lead to privilege escalations, password extractions, and other confidential data from Windows PCs.
The enumerations are carried out in a way that does not arouse the suspicion of certain protection systems on the PC. It also includes enumerations that are not found in some existing scripts like WinPeas. The formatting has also been improved compared to WinChecker V1.
Through this script, you will also find enumerations via external programs. For now, I have added WESNG (https://github.com/bitsadmin/wesng).

### Pictures

Some bad configuration enumerations :
![WinAuditer](https://github.com/raphaelthief/WinChecker/blob/main/Pictures/Badconfig.JPG "WinAuditer")


Some credencial enumerations :

![WinAuditer](https://github.com/raphaelthief/WinChecker/blob/main/Pictures/creds.JPG "WinAuditer")


Displaying installed softwares with their actual versions :
![WinAuditer](https://github.com/raphaelthief/WinChecker/blob/main/Pictures/Installed.JPG "WinAuditer")


Permissions enumerations :
![WinAuditer](https://github.com/raphaelthief/WinChecker/blob/main/Pictures/Permissions.JPG "WinAuditer")


Wesng intallation and execution :
![WinAuditer](https://github.com/raphaelthief/WinChecker/blob/main/Pictures/WESNG.JPG "WinAuditer")

![WinAuditer](https://github.com/raphaelthief/WinChecker/blob/main/Pictures/wes.JPG "WinAuditer")


Wifi profiles enumeration and output :

![WinAuditer](https://github.com/raphaelthief/WinChecker/blob/main/Pictures/Wifi1.JPG "WinAuditer")

![WinAuditer](https://github.com/raphaelthief/WinChecker/blob/main/Pictures/Wifi2.JPG "WinAuditer")


### Features

**Main execution :**
- Check admin rights for execution
- Show help menu with links to get tricks and exploit associated
- UTF8 set


**User and Computer infos :**
- Username
- User profile
- Hostname
- Active session
- User accounts
- Local groups
- Whoami
- Os caption, version and architecture
- Environnement
- System global infos
- Installed softwares and softwares versions
- Installed softwares location on regedit


**Network :**
- IP Configuration
- Network shares
- Active network connections
- Routing table
- ARP cache
- Host file check


**Credencial search :**
- Credencial file search
- Configuration files search
- Registry password storage
- Group policy preferences password
- Cloud credential files
- Microsoft credential files
- Check appcmd.exe
- DPAPI master keys
- Windows password cache
- SAM access files
- WiFi profiles and outputs creds
- Chromium interesting files (History, passwords, credit cards, autofills, etc ...)


**Active security :**
- Active endpoint protection
- Windows Defender exclusions
- Firewall state
- Firewall global settings


**Running processes and services :**
- List All Processes and Services (Table Format)
- List Processes and Services for System Account (Table Format)
- List Processes and Services with admin rights (Table Format)
- Check permissions for processes not in System32 folder


**Missconfigurations :**
- Unquoted paths
- AlwaysInstalledElevated
- Check user actions, security events, or system changes
- Check configuration settings related to event log forwarding
- Check local Administrator Password Solution (LAPS)
- Check LSA protection
- Check WDigest authentication protocol
- Check startup registry path
- Check startup folders with files
- Check startup folders permissions
- Check schelduled tasks
- UAC status
- eventvwr process locations


**PS infos :**
- Powershell V2 Version
- Powershell V5 Version
- Transcriptions
- Module logging
- Script logging
- Powershell commands history


**Other :**
- Missing updates
- Checking dependencies for externals installations (python, internet, etc ...)


**Clipboard infos :**
- Get current clipboard
- Get all clipboard history


**External programs :**
- WESNG (CVE enums) : https://github.com/bitsadmin/wesng
