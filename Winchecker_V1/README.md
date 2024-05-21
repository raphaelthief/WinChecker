WinChecker aims to scan any Windows environment for potential vulnerabilities related to misconfigurations that could lead to password extraction, privilege escalations, or installation backdoors. While creating this tool, I am not reinventing the wheel. However, I am bringing a different perspective to the execution of these tools through specific additions and a different presentation of the extracted results.

![WinChecker](https://github.com/raphaelthief/WinChecker/blob/main/Pictures/Main.JPG "WinChecker")

## Disclaimer

I am not responsible for the use you will make of this tool. Its purpose is solely to be used by the cybersecurity community who wish to use tools other than those already provided in their own environment or with the permission of the owners of those environments.

## WinCheck Features

### WindowsEnum

- Check admin rights for execution
- Get user infos
- Get all account users
- Local groups
- Current user logged
- Settings privileges account with the actual rights
- Get OS version, architecture and name
- Networks cards, updates, proc, region etc ...
- Get mounted disks
- Get machine environnement (Temp location, windir, userdomain, etc ...)
- Get installed software with versions
- Installed softwares from reg keys : get location of each
- Ipconfig /all
- List all the shares currently configured on the computer
- Display the IP routing table
- Display the current ARP 
- Display network statistics, connections, and port information
- DNS Windows file
- Display the contents of the DNS resolver cache
- AV & co on system
- Get all exclusions of Defender
- Firewall command update
- Running services
- Process, PID, Services
- Check permissions from active processes and associated folders
- Executable file permissions on services with non-system32 paths
- Check the permissions of each directory listed in the system PATH environment variable
- Hijacking folder locations without quotes
- Startup stuffs from regedit, startup folder & scheduled tasks
- GPO AlwaysInstallElevated on registry
- Security updates set with their versions
- Check user actions, security events, or system changes
- Retrieve configuration settings related to event log forwarding
- Check whether the Local Administrator Password Solution (LAPS)
- Check LSA protection
- Check WDigest authentication protocol is configured to store plaintext passwords in memory on the system
- Determine the number of cached logon credentials allowed on the system
- Determine whether User Account Control (UAC) is enabled or disabled on the system
- PowerShell settings
	- PowerShell v2 Version
	- PowerShell v5 Version
	- Transcriptions Settings
	- Module logging settings
	- Scriptblog logging settings
	- PowerShell default transcript history
	- PowerShell history file
- Check potentially risky permissions are granted to specific users or groups
- Check for the existence of various sysprep-related files and configuration files 
- Check for SiteList.xml
- Check for AppCmd

### PassEnum

- Check admin rights for execution
- List interesting files in directories
	- sysprep.inf
	- sysprep.xml
	- sysprep\\sysprep.xml
	- Panther\\Unattend\\Unattended.xml
- Enum strict passwords files with all extension (Dates infos)
	- pass.* password.* passwords.* creds.* credencials.* vnc.* mdp.* motsdepasse.* motdepasse.* secret.* confidentiel.* confidential.* sensible.*
- Get FileZilla infos and creds
- Enum all config files (only dir)
- Enum other interesting stuff
	- RDCMan.settings == *.rdg == *_history == .sudo_as_admin_successful == .profile == *bashrc == httpd.conf == *.plan == .htpasswd == .git-credentials == *.rhosts == hosts.equiv == Dockerfile == docker-compose.yml == TypedURLs == TypedURLsTime == places.sqlite == key3.db == key4.db == credentials.db == access_tokens.db == accessTokens.json == legacy_credentials == azureProfile.json == unattend.txt == access.log == error.log == *.gpg == *.pgp == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12 == *.der == *.csr == *.cer == known_hosts == id_rsa == id_dsa == *.ovpn == anaconda-ks.cfg == hostapd.conf == rsyncd.conf == cesi.conf == supervisord.conf == tomcat-users.xml == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == unattend.xml == unattended.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == groups.xml == services.xml == scheduledtasks.xml == printers.xml == drives.xml == datasources.xml == php.ini == https.conf == https-xampp.conf == httpd.conf == my.ini == my.cnf == access.log == error.log == server.xml == SiteList.xml == ConsoleHost_history.txt == setupinfo == setupinfo.bak
- Enum sensitive webbrowsers files
	- Cookies
	- Web Data
	- Login Data
	- History
	- Snapshots
- Enum registry stored passwords
- Enum global regedit 
- GPP Passwords search
- Cloud pass
	- SystemDrives
		- .aws == credentials == gcloud == credentials.db == legacy_credentials == access_tokens.db == .azure == accessTokens.json == azureProfile.json
	- Windir
		- .aws == credentials == gcloud == credentials.db == legacy_credentials == access_tokens.db == .azure == accessTokens.json == azureProfile.json
- Microsoft Data Protection API 
- Windows Vault
- Wi-Fi credencials
- Get last clipboard stored
- PS history
