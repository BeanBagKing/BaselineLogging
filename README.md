# BaselineLogging
Automating the baseline logging settings found here: https://nullsec.us/windows-baseline-logging/

Work in progress. If there are already settings in place, this may clobber them.

```
Only baselineLogging.ps1 is needed, all other files are fetched.
Run from Administrator prompt
Run
  Set-ExecutionPolicy RemoteSigned -Force
before starting.
```

* Will also set explorer to show file extensions, and set dangerous extensions to be opened with notepad.exe
* MachinePol.xml contains the local policy settings to be imported
* audit.csv contains the Advanced Audit Policy Configuration settings to be imported
* Network connection needed to download sysmon, sysmon configuration, MachinePol.xml, and audit.csv

### References
* https://web.archive.org/web/20181018000009/http:/brandonpadgett.com/powershell/Local-gpo-powershell/
* https://serverfault.com/questions/848388/how-to-edit-local-group-policy-with-a-script
* https://github.com/dlwyatt/PolicyFileEditor
* Also general references regarding logging at the bottom of https://nullsec.us/windows-baseline-logging/

### Description
Hey, this is mostly for keywords. This attempts to automate all the settings I have in my baseline logging post. In addition to the typical local group policy settings and advanced configuration settings, such as logon events, and command line logging, this will create the necessary directories for PSTranscription files, the scheduled task to clean them up, download and install Sysmon with the Swift on Security config, and enable firewall logging. 

This works well, in my limited testing, for new systems and/or forensic sandboxes or other temporary systems. An enterprise environment should test these settings to ensure they don't overwhelm their environment, deploy via a proper mechanism (e.g. GPO), and **CENTRALIZE YOUR LOGS!** Please, please centralize them. If you can't however, this is a good start. I have expanded the storage for security logs from 20mb to 100mb here. I would recommend ensuring at least 90 days are retained for all important logs in production.

### ToDo
* test for audit.csv path and file, don't clobber current settings if it's already there

### Exporting Current Policies
```
gpupdate /force

$MachineDir = "$env:windir\system32\GroupPolicy\Machine\registry.pol"
$UserDir = "$env:windir\system32\GroupPolicy\User\registry.pol"

Get-PolicyFileEntry -Path $MachineDir -All | Export-Clixml -Path C:\MachinePol.xml
Get-PolicyFileEntry -Path $UserDir -All | Export-Clixml -Path C:\UserPol.xml
```

### This is just a sample of the options availible to Advanced Audit Settings 
List these with `auditpol /get /category:*`
```
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Audit Process Creation,{0cce922b-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Process Termination,{0cce922c-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit RPC Events,{0cce922e-69ae-11d9-bed3-505054503030},Failure,,2
,System,Audit Token Right Adjusted,{0cce924a-69ae-11d9-bed3-505054503030},No Auditing,,0
```
