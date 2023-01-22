# BaselineLogging
Automating the baseline logging settings found here: https://nullsec.us/windows-baseline-logging/

Work in progress. If there are already settings in place, this may clobber them.

```
Only baselineLogging.ps1 is needed, all other files are fetched.
Run from Administrator prompt
Run
  Set-ExecutionPolicy RemoteSigned -Force
before starting. Script will change it back to the default (Restricted) when it's finished
```

* Will also set explorer to show file extensions, and set dangerous extensions to be opened with notepad.exe
* MachinePol.xml contains the local policy settings to be imported
* audit.csv contains the Advanced Audit Policy Configuration settings to be imported
* Network connection needed to download sysmon, sysmon configuration, MachinePol.xml, and audit.csv

### References
* https://web.archive.org/web/20181018000009/http:/brandonpadgett.com/powershell/Local-gpo-powershell/
* https://serverfault.com/questions/848388/how-to-edit-local-group-policy-with-a-script
* https://github.com/dlwyatt/PolicyFileEditor

### Description
Hey, this is mostly for keywords. This attempts to automate all the settings I have in my baseline logging post. In addition to the typical local group policy settings and advanced configuration settings, such as logon events, and command line logging, this will create the necessary directories for PSTranscription files, the scheduled task to clean them up, download and install Sysmon with the Swift on Security config, and enable firewall logging. 

This works well, in my limited testing, for new systems and/or forensic sandboxes or other temporary systems. An enterprise environment should test these settings to ensure they don't overwhelm their environment and **CENTRALIZE YOUR F@#$# LOGS!** Please, please centralize them. If you can't however, this is a good start. I would also (and may add this later), expand the default storage space for logs in order to ensure a long enough retention period. 

### ToDo
* test for audit.csv path and file, don't clobber current settings if it's already there
