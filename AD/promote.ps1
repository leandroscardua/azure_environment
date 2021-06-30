Param (
    	[Parameter(Mandatory=$true)] [string] $domainnamead,
	[Parameter(Mandatory=$true)] [string] $netbiosnamead,
	[Parameter(Mandatory=$true)] [string] $safemodepassword
)

Import-Module ServerManager
$regkey = test-path hklm:\software\FTCAD
if ($regkey -eq $true) {exit}
else {
# Turn Off Windows Firewall
netsh advfirewall set allprofiles state off
# Set Winrm trust for remote powershell
Set-Item wsman:\localhost\client\trustedhosts * -Force
# Install ADDS prerequisites
Add-WindowsFeature RSAT-AD-Tools
Add-WindowsFeature -Name "ad-domain-services" -IncludeAllSubFeature -IncludeManagementTools
Add-WindowsFeature -Name "dns" -IncludeAllSubFeature -IncludeManagementTools 
Add-WindowsFeature -Name "gpmc" -IncludeAllSubFeature -IncludeManagementTools
REG ADD HKLM\Software\FTCAD /v Data /t Reg_SZ /d "Installed"
# Windows PowerShell script for AD DS Deployment
$domainname = "$domainnamead" 
$netbiosName = "$netbiosnamead" 
#$safemodepassword = "$safemodepassword" | ConvertTo-SecureString -AsPlainText -Force
Import-Module ADDSDeployment
Install-ADDSForest `
-CreateDnsDelegation:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainMode "WinThreshold" `
-DomainName $domainname `
-DomainNetbiosName $netbiosName `
-ForestMode "WinThreshold" `
-InstallDns:$True `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SafeModeAdministratorPassword $safemodepassword `
-SysvolPath "C:\Windows\SYSVOL" `
-Force:$true}
# via https://gallery.technet.microsoft.com/scriptcenter/Install-Domain-Controller-a172b4a0
