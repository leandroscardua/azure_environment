Param (
    	[Parameter(Mandatory=$true)] [string] $VmAdminUsername,
    	[Parameter(Mandatory=$true)] [string] $VmAdminPassword,
    	[Parameter(Mandatory=$true)] [string] $SqlLoginUsername,
    	[Parameter(Mandatory=$true)] [string] $SqlLoginPassword,
 	[Parameter(Mandatory=$true)] [string] $SvcSecusername,
	[Parameter(Mandatory=$true)] [string] $SvcSecPassword,
    	[Parameter(Mandatory=$true)] [string] $UserNamedomainadmin
)

Install-PackageProvider -Name 'NuGet' -RequiredVersion '2.8.5.201' -Force
Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted'
Install-Module -Name 'SqlServer' -AllowClobber -Force

Install-PackageProvider -Name 'NuGet' -RequiredVersion '2.8.5.201' -Force
Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted'
Install-Module -Name 'dbatools' -AllowClobber -Force

# This script will be executed by the custom script extension in the SYSTEM user context. We need to talk to
# SQL Server with the VM administrator account, which is the default SQL administrator in the marketplace image.
# This PSCredential will allow us to act as the VM administrator.
$secureVmAdminPassword = ConvertTo-SecureString -String $VmAdminPassword -AsPlainText -Force
$vmAdminCredential = New-Object -TypeName 'PSCredential' -ArgumentList "$env:ComputerName\$VmAdminUsername", $secureVmAdminPassword
$secureSQLAdminPassword = ConvertTo-SecureString -String $SqlLoginPassword -AsPlainText -Force
$secureSCVSecPassword = ConvertTo-SecureString -String $SvcSecPassword -AsPlainText -Force

# Enable mixed mode authentication (service restart required). By default the marketplace image is Windows
# authentication only. We need to do this in the execution context of the VM administrator.
Invoke-Command -ComputerName 'localhost' -Credential $vmAdminCredential -ArgumentList @($SqlLoginUsername, $SqlLoginPassword, $SvcSecusername, $SvcSecPassword, $UserNamedomainadmin) -ScriptBlock {
    Param (
        	[Parameter(Mandatory=$true)] [string] $SqlLoginUsername,
        	[Parameter(Mandatory=$true)] [string] $SqlLoginPassword,
		[Parameter(Mandatory=$true)] [string] $SvcSecusername,
        	[Parameter(Mandatory=$true)] [string] $SvcSecPassword,
        	[Parameter(Mandatory=$true)] [string] $UserNamedomainadmin
    )
    Invoke-Sqlcmd -ServerInstance 'localhost' -Database 'master' `
        -Query "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 2"
    Restart-Service -Name 'MSSQLServer'

	$secureSQLAdminPassword = ConvertTo-SecureString -String $SqlLoginPassword -AsPlainText -Force
	$secureSCVSecPassword = ConvertTo-SecureString -String $SvcSecPassword -AsPlainText -Force

	Import-Module -Name dbatools
	Set-DbaLogin -SqlInstance localhost -Login $SqlLoginUsername -SecurePassword $secureSQLAdminPassword -Enable -Confirm:$false
    New-DbaLogin -SqlInstance localhost -Login $UserNamedomainadmin
    Set-DbaLogin -SqlInstance localhost -Login $UserNamedomainadmin -AddRole sysadmin

	Update-DbaServiceAccount -ComputerName localhost -ServiceName 'MSSQLSERVER','SQLSERVERAGENT' -Username $SvcSecusername -SecurePassword $secureSCVSecPassword -Confirm:$false
   
}
# add Fireall rules to enable remote access to SQL Server##
New-NetFirewallRule -DisplayName 'SQL Server' -Direction 'Inbound' -Protocol 'TCP' -LocalPort 1433 -Action 'Allow' -Profile 'Domain'
New-NetFirewallRule -DisplayName 'SQL Admin Connection' -Direction 'Inbound' -Protocol 'TCP' -LocalPort 1434 -Action 'Allow' -Profile 'Domain'
New-NetFirewallRule -DisplayName 'SQL Database Management' -Direction 'Inbound' -Protocol 'UDP' -LocalPort 1434 -Action 'Allow' -Profile 'Domain'
New-NetFirewallRule -DisplayName 'SQL Service Broker' -Direction 'Inbound' -Protocol 'TCP' -LocalPort 4022 -Action 'Allow' -Profile 'Domain'
New-NetFirewallRule -DisplayName 'SQL Debugger/RPC' -Direction 'Inbound' -Protocol 'TCP' -LocalPort 135 -Action 'Allow' -Profile 'Domain'
New-NetFirewallRule -DisplayName 'SQL Analysis Services' -Direction 'Inbound' -Protocol 'TCP' -LocalPort 2383 -Action 'Allow' -Profile 'Domain'
New-NetFirewallRule -DisplayName 'SQL Browser' -Direction 'Inbound' -Protocol 'TCP' -LocalPort 2382 -Action 'Allow' -Profile 'Domain'

#via https://anchorloop.com/2018/07/14/configure-sql-server-with-azure-vm-extensions/
