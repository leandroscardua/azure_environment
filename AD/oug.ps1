Param (
    	[Parameter(Mandatory=$true)] [string] $OUPathWEBAPP,
	[Parameter(Mandatory=$true)] [string] $OUPathAPP,
	[Parameter(Mandatory=$true)] [string] $OUPath,
	[Parameter(Mandatory=$true)] [string] $filegpourl,
	[Parameter(Mandatory=$true)] [string] $defaultpass,
	[Parameter(Mandatory=$true)] [string] $usernamead,
	[Parameter(Mandatory=$true)] [string] $usernamenumber,
	[Parameter(Mandatory=$true)] [string] $FQDNDomain
)

Import-Module ActiveDirectory
Import-Module grouppolicy

# Create OU, GPO #

New-ADOrganizationalUnit -Name "Servers"

New-ADOrganizationalUnit -Name "APP" -Path "$OUPath"

New-ADOrganizationalUnit -Name "Web" -Path "$OUPath"

# Download the GPO to restore #

New-Item -Path C:\backupgpo -ItemType directory

$Url = "$filegpourl"
$Path = "C:\backup\gpo.zip"
(New-Object System.Net.WebClient).DownloadFile($Url,$Path)

Expand-Archive -Path C:\backupgpo\gpo.zip -DestinationPath C:\backupgpo\

## Create new GPO and Restore the GPOs##

New-GPO -Name GPO_APP_Server

import-gpo -BackupGpoName "GPO_APP_Server" -TargetName "GPO_APP_Server" -path c:\backup

New-GPLink -Name "GPO_APP_Server" -Target "$OUPathAPP"

import-gpo -BackupGpoName "Default Domain Policy" -TargetName "Default Domain Policy" -path c:\backup

New-GPLink -Name "Default Domain Policy" -Target "$OUPath"

New-GPO -Name MSDTC

import-gpo -BackupGpoName "MSDTC" -TargetName "MSDTC" -path c:\backup

New-GPLink -Name "MSDTC" -Target "$OUPathWEBAPP"

New-GPLink -Name "GPO_APP_Server" -Target "$OUPathWEBAPP"


# Create user and group#

New-ADGroup -Name DBAdmin -GroupScope Global

$pwd = "$defaultpass" | ConvertTo-SecureString -AsPlainText -Force

# Create Admin Users

New-ADUser `
    -Name "Leandro" `
    -SamAccountName 'leandro' `
    -UserPrincipalName 'leandro@$FQDNDomain' `
    -AccountPassword $pwd `
    -Enabled $True
Add-ADGroupMember -Identity "DBAdmin" -Members leandro
Add-ADGroupMember -Identity "Domain Admins" -Members leandro

Create Service account

New-ADUser `
    -Name "SvcSec" `
    -SamAccountName 'SvcSec' `
    -UserPrincipalName 'SvcSec@$FQDNDomain' `
    -AccountPassword $pwd `
    -ChangePasswordAtLogon $false `
    -PasswordNeverExpires $true `
    -Enabled $True

# Creation of "$usernamead" users #

$user="$usernamead"
$pwd = "$defaultpass" | ConvertTo-SecureString -AsPlainText -Force
$count=1..$usernamenumber
foreach ($i in $count)
{ 
New-AdUser -Name $user$i -SamAccountName $user$i -Enabled $True -AccountPassword $pwd -ChangePasswordAtLogon $false -UserPrincipalName $user$i@$FQDNDomain -CannotChangePassword $true -PasswordNeverExpires $true
Add-ADGroupMember -Identity "DBAdmin" -Members $user$i
}
