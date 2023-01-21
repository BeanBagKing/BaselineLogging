# Install Necessary Modules
Write-Host "-------------- Starting --------------" -ForegroundColor Green
Write-Host "Installing Inital Necessay Modules" -ForegroundColor Yellow
$startingPolicy = Get-ExecutionPolicy # Store this to revert later
Set-ExecutionPolicy RemoteSigned -Force
Install-PackageProvider -Name NuGet -Force
Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
Install-Module -Name PolicyFileEditor -RequiredVersion 3.0.0 -Scope CurrentUser # This is what allows us to set local GPO
Import-Module PolicyFileEditor

# Create the PSTranscription directory for later
Write-Host "Creating PSTranscription Directory" -ForegroundColor Yellow
$PSTranscriptionDir = "C:\PStranscription"
if (Test-Path -Path $PSTranscriptionDir) {
    Write-Host "PSTranscription Path Exists, Skipping"
}
else {
    New-Item -ItemType Directory -Force -Path $PSTranscriptionDir
}

# Import settings from PolicyFileEditor File
Write-Host "Importing Local Policy Settings" -ForegroundColor Yellow
$MachineDir = "$env:windir\system32\GroupPolicy\Machine\registry.pol"
$MachinePols = Import-Clixml -Path 'MachinePol.xml'
foreach ($MachinePol in $MachinePols) {
    Write-Host "importing " $MachinePol.Key " " $MachinePol.ValueName
    $MachinePol | Set-PolicyFileEntry -Path $MachineDir
}

## Import advanced settings from audit.csv File
Write-Host "Importing Advanced Settings" -ForegroundColor Yellow
$AdvancedDir = "$env:windir\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit"
if (Test-Path -Path $AdvancedDir) {
    Write-Host "Audit Path Exists, Skipping"
}
else {
    New-Item -ItemType Directory -Force -Path $AdvancedDir
}
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/BeanBagKing/BaselineLogging/main/audit.csve" -OutFile "$AdvancedDir\audit.csv"

# Force audit policy subcategory settings 
Write-Host "Forcing Subcategory Settings" -ForegroundColor Yellow
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -PropertyType DWord -Force 

# Enable Prefetch on Servers
Write-Host "Enabling Prefetch On Servers" -ForegroundColor Yellow
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
if ( $osInfo.ProductType -ne 1 ) {
    # 1 = Workstation, 2 = DC, 3 = Server
    Write-Host "Server OS Found, Setting"
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 3 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Prefetcher" /v MaxPrefetchFiles /t REG_DWORD /d 8192 /f
    Enable-MMAgent –OperationAPI
    net start sysmain
}
else { 
    Write-Host "Workstation OS Found, Skipping" 
}

# Create PowerShell Profile.ps1
Write-Host "Creating Profile.ps1 File" -ForegroundColor Yellow
$file = "$env:windir\System32\WindowsPowerShell\v1.0\profile.ps1"
New-Item $file -ItemType File -Force
Add-Content $file "`$LogCommandHealthEvent = `$true"
Add-Content $file "`$LogCommandLifecycleEvent = `$true"

# Sign PowerShell Profile.ps1
Write-Host "Signing Profile.ps1 File" -ForegroundColor Yellow
$codeCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=LocalSelfSigned" }
if (-Not $codeCertificate) {
    Write-Host "No Cert, Generating..."
    $authenticode = New-SelfSignedCertificate -Subject "LocalSelfSigned" -CertStoreLocation Cert:\LocalMachine\My -Type CodeSigningCert
    $rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("Root", "LocalMachine")
    $rootStore.Open("ReadWrite")
    $rootStore.Add($authenticode)
    $rootStore.Close()
    $publisherStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("TrustedPublisher", "LocalMachine")
    $publisherStore.Open("ReadWrite")
    $publisherStore.Add($authenticode)
    $publisherStore.Close()
    $codeCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=LocalSelfSigned" }
}
else {
    Write-Host "Cert Exists, using it..."
}
Set-AuthenticodeSignature -FilePath "$env:windir\System32\WindowsPowerShell\v1.0\profile.ps1" -Certificate $codeCertificate -TimeStampServer http://timestamp.digicert.com


# Disable powershell v2
Write-Host "Disabling Powershell v2" -ForegroundColor Yellow
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

# Install Sysmon
Write-Host "Installing Sysmon" -ForegroundColor Yellow
$SysmonDir = "$env:windir\Sysmon"
New-Item -ItemType Directory -Force -Path $SysmonDir
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$SysmonDir\sysmonconfig-export.xml"
Invoke-WebRequest -Uri "https://live.sysinternals.com/Sysmon.exe" -OutFile "$SysmonDir\Sysmon.exe"
#C:\Windows\Sysmon\Sysmon.exe -accepteula -i c:\Windows\Sysmon\sysmonconfig-export.xml
Start-Process -FilePath "$env:windir\Sysmon\Sysmon.exe" -ArgumentList "-accepteula -i $env:windir\Sysmon\sysmonconfig-export.xml"


# Remove Old PSTranscription
Write-Host "Creating Scheduled Task to Remove Old PSTranscription Files" -ForegroundColor Yellow
$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '"Get-ChildItem C:\PSTranscription -Recurse | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-90) } | Remove-Item –Recurse"'
$trigger = New-ScheduledTaskTrigger -Daily -At 9am
$description = "Cleans PSTranscription Logs (Default: Over 90 Days Old)"
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Cleanup PSTranscription" -Description $description -Settings $Settings -RunLevel Highest

## Things left to do
# test for audit.csv path and file, don't clobber current settings if it's already there
# store audit.csv and MachinePol.xml in this file, less moving stuff around?
# Get current execution policy, and reset it to what it was once the script is finished
