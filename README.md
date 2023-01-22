# BaselineLogging
Automating the baseline logging settings found here: https://nullsec.us/windows-baseline-logging/

Work in progress. If there are already settings in place, this may clobber them.

Run from Administrator prompt
Run
  Set-ExecutionPolicy RemoteSigned -Force
before starting. Script will change it back to the default (Restricted) when it's finished

References
https://web.archive.org/web/20181018000009/http:/brandonpadgett.com/powershell/Local-gpo-powershell/
https://serverfault.com/questions/848388/how-to-edit-local-group-policy-with-a-script
https://github.com/dlwyatt/PolicyFileEditor
