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

Will also set explorer to show file extensions, and set dangerous extensions to be opened with notepad.exe

MachinePol.xml contains the local policy settings to be imported

audit.csv contains the Advanced Audit Policy Configuration settings to be imported

Network connection needed to download sysmon, sysmon configuration, MachinePol.xml, and audit.csv

References
https://web.archive.org/web/20181018000009/http:/brandonpadgett.com/powershell/Local-gpo-powershell/
https://serverfault.com/questions/848388/how-to-edit-local-group-policy-with-a-script
https://github.com/dlwyatt/PolicyFileEditor
