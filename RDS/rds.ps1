#Install Roles

Get-WindowsFeature | ? { $_.Name -match "RDS-Licensing|RDS-RD-Server" } | Install-WindowsFeature



#Allow RDP Access to the server

Set-ItemProperty "hklm:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0

#Get-ItemProperty "hklm:\SYSTEM\CurrentControlSet\Control\Terminal Server" 



#Per Device  

#$licenseMode = 2



#Per User  

$licenseMode = 4



#Licensing Server  

$licenseServer = "$env:computername.$env:userdnsdomain"



Set-ItemProperty "hklm:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core\" -Name "LicensingMode" -Value $licenseMode  

#Get-ItemProperty "hklm:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core\" -Name "LicensingMode"  

New-Item "hklm:\SYSTEM\CurrentControlSet\Services\TermService\Parameters\LicenseServers"

New-ItemProperty "hklm:\SYSTEM\CurrentControlSet\Services\TermService\Parameters\LicenseServers" -Name SpecifiedLicenseServers -Value $licenseServer -PropertyType "MultiString"  

#Get-ItemProperty "hklm:\SYSTEM\CurrentControlSet\Services\TermService\Parameters\LicenseServers" -Name SpecifiedLicenseServers   



#Allow Shadowing Users

# Values: 0 (No Remote Control), 1 (Full Control with user's permission), 2 (Full Control without user's permission), 3 (View Session with user's permission), 4 (View Session without user's permission)

New-ItemProperty "hklm:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name Shadow -Value 2 -PropertyType "DWORD"


# Install application##

Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) |Out-null

choco install putty.install -y
choco install redis-desktop-manager -y
choco install notepadplusplus.install -y
choco install winscp.install -y


#Update GPO for Shadowing Users

gpupdate /force


#Restart the computer

Restart-Computer