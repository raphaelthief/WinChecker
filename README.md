# WinChecker
Theses scripts aims to scan any Windows environment for potential vulnerabilities related to misconfigurations that could lead to password extraction, privilege escalations, or installation backdoors. While creating this tool, I am not reinventing the wheel. However, I am bringing a different perspective to the execution of these tools through specific additions and a different presentation of the extracted results.


## Disclaimer
I am not responsible for the use you will make of this tool. Its purpose is solely to be used by the cybersecurity community who wish to use tools other than those already provided in their own environment or with the permission of the owners of those environments.


## Last version aviable
Check for Winchecker_V2_WinAuditer

![WinAuditer](https://github.com/raphaelthief/WinChecker/blob/main/Pictures/Main2.JPG "WinAuditer")


## Troubleshooting

- Winchecker_V1 - WindowsEnum.bat
This tool may generate certain DNS issues on the machine on which it is run. If you encounter such an issue, please restart the computer and everything will return to normal

- Winchecker_V2_WinAuditer - WinAuditer.bat
Make sure to execute the script in a complete directory structure without spaces.

Exemple :

Don't run in : "C:\user\Joe\Windows Auditer\WinAuditer.bat"

Run in : "C:\user\Joe\Windows_Auditer\WinAuditer.bat"
