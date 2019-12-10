
$versionps = 'DeploymentVMAzureOnAzure v1.0'

<#
DeploymentStorageAccountAzure
(C) 
TODO Enhancements
[X] Before create any new resource the script will check if the resource exist on teh Azure Subscription
[X] Script will create all resource on Azure (Resourge Group, Virtual Network, Storage Account, Public Ip, Storage account and VM)
[X] Install VM on Azure (Windows and Linux)
[X] Automatic creation of a New Domain controller in a New Forest as a VM, if you need to change any configuration the file this is the file" \AD\Promote.ps1
[X] Automatic creation of the Users, groups, OU and GPO Base a paraments on the Powershell script \AD\oug.ps1 
[X] All The Windows VMs will be automatic join on the Domain
[X] On the Linux VM, the users will be create on system with sudo privilege on the system.
[X] On the RDS server, During the VM process, the RDS features are enabled to allow more than 2 users at the same time on the RDP connection. Using trial license for 180 Days, also
    the installation of WinSCP, Putty, RedisManager, Notepad++ for all users, the script is located \RDS\rds.ps1
[X] On the SQL Server VM , During the installation, will enable mixmode, Enable and Change the password of SA, Create a SQL User and run the SQL Server and SQL Agent with this user, 
	and add the VM on the Availability group to work with the load balance.
[X] On the Load Balance configuration, we create two frontend IP base on the SQL cluster configuration, the variables with the Ip are: $LBIp, $LBIpReport
[ ] Add Linux VM on the Domain ( if necessary)
#>

###########################
### C O N N E C T I O N ###
###########################

$env = Get-AzureRmEnvironment -Name AzureUSGovernment
Login-AzureRmAccount -Environment $env  
$subname = ""   # Enter the name of teh subscription here
$Id = Select-AzureRmSubscription -SubscriptionName "$subname"


#########################
###       Notes       ###
#########################

### Please, Be carefull when change the variables on the script.####
# $subname: subscription selection on Azure
# $convname: The convention name of the objects will start with this name, the objects can be: VM, Storage account, VNET, NSG and etc..( The name needs to in CAPITAL LETTERS )
# $officeip: This Ip will have external access to Azure VM, Storage accounts, be careful with this IP
# $rdsname" it will be the name to access the RDP server by the name: using azure governament the access will be $rdsname.$location.azureaddress


#########################
#### GLOBAL SETTINGS ####
#########################

# Please, Change the Name of VM from the Application part #
# By Default teh Script will deploy one Domain and one RDS Server.

$WEBAPPVMnumber = "1"  # WEB VM
$APPVMumber = "1"      # APP VM
$SQLVMumber = "1"      # SQL Server VM
$REDISVMNumber = "1"   # Linux VM
$BISQLVMnumber = "1"   # BI SQL Server

$convname = "TEST" # The value needs to be in CAPITAL LETTERS and together #
$uploadfolder = 'C:\azure\environment'
$officeip = "XXX.XXX.XXX.XXX" # Add your public Ip here, to allow the external access
$rdsname = "rds"
#Password of all user during the deployment will use this password and convention for the name ##
$defaultpass = "enter a password here"
$username ="leandro_user"
$usernamenumber = "5"

$location = "eastus2" # Change the location base with your requirements
$vnetname = ("$convname"+"-VNET")
$resourcegroupname = ("$convname"+"-RG")
$diagstorageacc = ($convname.ToLower() + "sa")
$addressprefix = "10.10.0.0/16"
$subnetname = ("$convname"+"-VNET")
$subnetadress = "10.10.1.0/24"
$storageaccountname = ($convname.ToLower() + "sa")
$storageContainer = "domain"
$fileNamepromote = "promote.ps1"
$fileNameoug = "oug.ps1"
$fileNamerds = "rds.ps1"
$fileNamesql = "sqlserver.ps1"
$fileNamegpo = "gpo.zip"
$fileNamelinux = "users.sh"
$subscription = $Id.Subscription.Id 
$nsgnameinternal = ("$convname"+"-Internal-NSG")
# Domain Credentials #
$FQDNDomain = "leandro.training"
$netbiosnamead =leandro"
$safemodepassword = "$defaultpass"
$UserName = "leandro\testadmin"
$PWDDomainUser = "$defaultpass"
$OUPath = "OU=Servers,DC=leandro,DC=training"
$OUPathAPP = "OU=APP,OU=Servers,DC=leandro,DC=training"
$OUPathWEBAPP = "OU=WEB,OU=Servers,DC=leandro,DC=training"
$SecurePassword = ConvertTo-SecureString $PWDDomainUser -AsPlainText -Force
$DomainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName,$SecurePassword
$ASGName = ("$convname" + "-AS")
$LBDatabase = ("$convname"+"DB-LB")
# IPs In use #
# 10.250.1.57, reserved for SQL Cluster IP.
$LBIp = "10.10.1.58"
$LBIpReport = "10.10.1.59"
$domaincontrollerip = "10.10.1.200"
$internalipRDS = "10.10.1.205"
$remoteserverip = $internalipRDS
$publicipname = ("$convname" + "PI")
# Local Admin Credentials #
$LocalAdmin = "testadmin"
$GetPassword = "$defaultpass"
$LocalSecurePassword = ConvertTo-SecureString $GetPassword -AsPlainText -Force
$LocalCredential = New-Object -TypeName System.Management.Automation.PSCredential $LocalAdmin,$LocalSecurePassword
$TimeZone = "Eastern Standard Time"
#SQL Server #
$SqlLoginUsername = "sa"
$SqlLoginPassword = "$defaultpass"
#SQL Server Service Account#
$SvcSecusername = "leandro\svcsec"
$SvcSecPassword = "$defaultpass"
#Windows VM Applications and Operation Information SKu,image and etc
$OfferNameWS = "WindowsServer"
$PubNameWS = "MicrosoftWindowsServer"
$SkuNameWS = "2016-Datacenter"
$VersionWS = "latest"
$VMSizeAPP = "Standard_DS2"
$VMSizeWEBAPP = "Standard_DS13_v2_Promo"
$VMSizeRDS = "Standard_DS13_v2_Promo"
$VMSizeDC = "Standard_DS12_v2_Promo"
$VMSizeBI = "Standard_DS13_v2_Promo"
#Windows VM Database Information SKu,image and etc
$OfferNameDB = "SQL2016SP2-WS2016"
$PubNameDB = "MicrosoftSQLServer"
$SkuNameDB = "SQLDEV"
$VersionDB = "latest"
$VMSizeDB = "Standard_DS12_v2_Promo"
#Linux VM Information SKU,image and etc
$OfferNameLX = "UbuntuServer"
$PubNameLX = "Canonical"
$SkuNameLX = "18.04-LTS"
$VersionLX = "latest"
$VMSizeLX = "Standard_DS2"


#########################
#RESOURCE GROUP SETTINGS#
#########################

Get-AzureRmResourceGroup -Name $resourcegroupname -ErrorVariable notPresent -ErrorAction SilentlyContinue | Out-Null
if ($notPresent)
{
    write-Host "DEPLOYING: The Resource Group $vnetname"
    New-AzureRmResourceGroup -Name $resourcegroupname -Location $location | Out-Null
}
else
{
    write-Host "The ResourceGroup $resourcegroupname already exist"
}

#########################
# VNET And NSG SETTINGS #
#########################

Get-AzureRmVirtualNetwork -Name $vnetname -ResourceGroupName $resourcegroupname -ErrorVariable notPresent -ErrorAction SilentlyContinue |Out-Null
if ($notPresent)
{
    write-Host "DEPLOYING: The Virtual Network $vnetname"
    $rdpRule = New-AzureRmNetworkSecurityRuleConfig -Name rdp-rule -Description "Allow RDP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 100 -SourceAddressPrefix $officeip -SourcePortRange * -DestinationAddressPrefix $internalipRDS -DestinationPortRange 3389
    $newsecuritygroup = New-AzureRmNetworkSecurityGroup -ResourceGroupName $resourcegroupname -Location $location -Name $nsgnameinternal -SecurityRules $rdpRule
    $newsubnet = New-AzureRmVirtualNetworkSubnetConfig -Name $subnetname -AddressPrefix $subnetadress -NetworkSecurityGroup $newsecuritygroup -ServiceEndpoint Microsoft.Storage
    New-AzureRmVirtualNetwork -Name $vnetname -ResourceGroupName $resourcegroupname -Location $location -AddressPrefix $addressprefix -Subnet $newsubnet |Out-Null
}
else
{
    write-Host "The VNET $vnetname Already Exist"

}

#########################
#STORAGE ACC SETTINGS####
#########################


Get-AzureRMStorageAccount -ResourceGroupName $resourcegroupname -Name $storageaccountname -ErrorVariable notPresent -ErrorAction SilentlyContinue |Out-Null
if ($notPresent)
{
write-Host "DEPLOYING: The Storage Account $storageaccountname"
New-AzureRmStorageAccount -EnableHttpsTrafficOnly $true -ResourceGroupName $resourcegroupname -Location $location -AccessTier Hot -SkuName Standard_LRS -Name $storageaccountname -Kind StorageV2 -NetworkRuleSet (@{bypass = "Logging,Metrics";
    ipRules=(@{IPAddressOrRange = "$officeip"; Action = "allow" });
    virtualNetworkRules=(@{VirtualNetworkResourceId = "/subscriptions/$subscription/resourceGroups/$resourcegroupname/providers/Microsoft.Network/virtualNetworks/$vnetname/subnets/$subnetname"; Action = "allow"});
    defaultAction = "Deny"}) |Out-Null
New-AzureRmStorageContainer -ResourceGroupName $resourcegroupname -StorageAccountName $storageaccountname -Name $storageContainer -PublicAccess Blob |Out-Null
}
else
{
    write-Host "The Storage Account $storageaccountname Already Exist"

}


#########################
#UPLLOAD FILES SETTINGS #
#########################

$storageAccountKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $resourcegroupname -Name $storageaccountname).Value[0]
$context = New-AzureStorageContext -StorageAccountName $storageaccountname -StorageAccountKey $storageAccountKey
Set-AzureRmCurrentStorageAccount -Context $Context

Get-AzureStorageBlob -Blob $fileNamepromote -Container $storageContainer  -Context $blobContext -ErrorVariable notPresent -ErrorAction SilentlyContinue |Out-Null
if ($notPresent)
{
Set-AzureStorageBlobContent -File "$uploadfolder\AD\$fileNamepromote" -container $storageContainer
}
else
{
write-Host "The File name $fileNamepromote Already Exist"
}
Get-AzureStorageBlob -Blob $fileNamegpo -Container $storageContainer  -Context $blobContext -ErrorVariable notPresent -ErrorAction SilentlyContinue |Out-Null
if ($notPresent)
{
Set-AzureStorageBlobContent -File "$uploadfolder\AD\$fileNamegpo" -container $storageContainer
}
else
{
write-Host "The File name $fileNamegpo Already Exist"
}
Get-AzureStorageBlob -Blob $fileNameoug -Container $storageContainer  -Context $blobContext -ErrorVariable notPresent -ErrorAction SilentlyContinue |Out-Null
if ($notPresent)
{
Set-AzureStorageBlobContent -File "$uploadfolder\AD\$fileNameoug" -container $storageContainer
}
else
{
write-Host "The File name $fileNameoug Already Exist"
}
Get-AzureStorageBlob -Blob $fileNameoug -Container $storageContainer  -Context $blobContext -ErrorVariable notPresent -ErrorAction SilentlyContinue |Out-Null
if ($notPresent)
{
Set-AzureStorageBlobContent -File "$uploadfolder\RDS\$fileNamerds" -container $storageContainer
}
else
{
write-Host "The File name $fileNamerds Already Exist"
}
Get-AzureStorageBlob -Blob $fileNamesql -Container $storageContainer  -Context $blobContext -ErrorVariable notPresent -ErrorAction SilentlyContinue |Out-Null
if ($notPresent)
{
Set-AzureStorageBlobContent -File "$uploadfolder\SQL\$fileNamesql" -container $storageContainer
}
else
{
write-Host "The File name $fileNamesql Already Exist"
}
Get-AzureStorageBlob -Blob $fileNamelinux -Container $storageContainer  -Context $blobContext -ErrorVariable notPresent -ErrorAction SilentlyContinue |Out-Null
if ($notPresent)
{
Set-AzureStorageBlobContent -File "$uploadfolder\Linux\$fileNamelinux" -container $storageContainer
}
else
{
write-Host "The File name $fileNamelinux Already Exist"
}
$filegpourl = (Get-AzureStorageBlob -Blob $fileNamegpo -Container $storageContainer).ICloudBlob.Uri.AbsoluteUri
$filelinux = (Get-AzureStorageBlob -Blob $fileNamelinux -Container $storageContainer).ICloudBlob.Uri.AbsoluteUri

###########################
#Availability SET SETTINGS#
###########################

Get-AzureRmAvailabilitySet -ResourceGroupName $resourcegroupname -Name $ASGName -ErrorVariable notPresent -ErrorAction SilentlyContinue |Out-Null
if ($notPresent)
{
write-Host "DEPLOYING: The Availability Set Group $storageaccountname"
New-AzureRmAvailabilitySet -ResourceGroupName $resourcegroupname -Name $ASGName -Location $location -PlatformUpdateDomainCount 1 -PlatformFaultDomainCount 1 |Out-Null
}
else
{
write-Host "The Availability Set Group $ASGName  Already Exist"
}


#########################
####  AD SETTINGS    ####
#########################

# VM Information #

$itemNumber = "1"
$VMName = "$convname"+"DC"+"$itemNumber"

Get-AzureRMVM -Name $VMName -ResourceGroupName $resourcegroupname  -ErrorVariable notPresent -ErrorAction SilentlyContinue |Out-Null
if ($notPresent)
{
write-Host "DEPLOYING: The New Azure VM $VMName"
# Networking #

$VNET = Get-AzureRmVirtualNetwork -Name $vnetname -ResourceGroupName $resourcegroupname
$NICName01 = $VMName + "-NIC1"
$TarSubnet01 = Get-AzureRmVirtualNetworkSubnetConfig -VirtualNetwork $VNET -Name $subnetname
$NIC01 = New-AzureRmNetworkInterface -Location $location -Name $NICName01 -ResourceGroupName $resourcegroupname -SubnetId $TarSubnet01.Id -PrivateIpAddress $domaincontrollerip

# VM PROFILE #

$VM = New-AzureRmVMConfig -VMName $VMName -VMSize $VMSizeDC -LicenseType "Windows_Server"
$VM = Add-AzureRmVMNetworkInterface -Id $NIC01.Id -VM $VM -Primary
$VM = Set-AzureRmVMSourceImage -Offer $OfferNameWS -PublisherName $PubNameWS -Skus $SkuNameWS -Version $VersionWS -VM $VM
$VM = Set-AzureRmVMOperatingSystem -ComputerName $VMName -Credential $LocalCredential -VM $VM -Windows -EnableAutoUpdate -ProvisionVMAgent -TimeZone $TimeZone
$VM = Set-AzureRmVMOSDisk -CreateOption fromImage -VM $VM -Caching ReadWrite -DiskSizeInGB 128 -Name "$VMName-OSDisk" -Windows
$VM = Set-AzureRmVMBootDiagnostics -Enable -ResourceGroupName $resourcegroupname -VM $VM -StorageAccountName $diagstorageacc

#Create the VM

New-AzureRmVM -Location $location -ResourceGroupName $resourcegroupname -VM $VM -Verbose

#DC Promo
Set-AzureRmVMCustomScriptExtension -Location $location -Name "Promotion" -VMName $VMName -ResourceGroupName $resourcegroupname -StorageAccountName $storageaccountname  -StorageAccountKey $storageAccountKey -ContainerName $storageContainer -FileName $fileNamepromote `
 -Argument "-domainnamead $FQDNDomain -netbiosnamead $netbiosnamead -safemodepassword $safemodepassword"

Start-Sleep -Seconds 300

Remove-AzureRmVMExtension -Name "Promotion" -ResourceGroupName $resourcegroupname -VMName $VMName -Force

#Create Users, Group and OU
Set-AzureRmVMCustomScriptExtension -Location $location -Name "oug" -VMName $VMName -ResourceGroupName $resourcegroupname -StorageAccountName $storageaccountname  -StorageAccountKey $storageAccountKey -ContainerName $storageContainer -FileName $fileNameoug `
    -Argument "-OUPathWEBAPP $OUPathWEBAPP -OUPathAPP $OUPathAPP -OUPath $OUPath -filegpourl $filegpourl -defaultpass $defaultpass -username $username -usernamenumber $usernamenumber"

# Change VNET DNS to add the machines ont he domain #
$vnet = Get-AzureRmVirtualNetwork -ResourceGroupName $resourcegroupname -name $vnetname
$vnet.DhcpOptions.DnsServers = $domaincontrollerip 
Set-AzureRmVirtualNetwork -VirtualNetwork $vnet
}
else
{
write-Host "The Azure VM $VMName Already Exist"
}


#########################
#   WEBAPP VM SETTINGS  #
#########################

For ($i=1; $i -le $WEBAPPVMnumber; $i++) {

# VM Information #

$itemNumber = "$i"
$VMName = "$convname"+"WEB"+"$itemNumber"

Get-AzureRMVM -Name $VMName -ResourceGroupName $resourcegroupname  -ErrorVariable notPresent -ErrorAction SilentlyContinue |Out-Null
if ($notPresent)
{
write-Host "DEPLOYING: The New Azure VM $VMName"
# Networking #

$VNET = Get-AzureRmVirtualNetwork -Name $vnetname -ResourceGroupName $resourcegroupname
$NICName01 = $VMName + "-NIC1"
$TarSubnet01 = Get-AzureRmVirtualNetworkSubnetConfig -VirtualNetwork $VNET -Name $subnetname
$NIC01 = New-AzureRmNetworkInterface -Location $location -Name $NICName01 -ResourceGroupName $resourcegroupname -SubnetId $TarSubnet01.Id

# VM PROFILE #

$VM = New-AzureRmVMConfig -VMName $VMName -VMSize $VMSizeWEBAPP -LicenseType "Windows_Server"
$VM = Add-AzureRmVMNetworkInterface -Id $NIC01.Id -VM $VM -Primary
$VM = Set-AzureRmVMSourceImage -Offer $OfferNameWS -PublisherName $PubNameWS -Skus $SkuNameWS -Version $VersionWS -VM $VM
$VM = Set-AzureRmVMOperatingSystem -ComputerName $VMName -Credential $LocalCredential -VM $VM -Windows -EnableAutoUpdate -ProvisionVMAgent -TimeZone $TimeZone
$VM = Set-AzureRmVMOSDisk -CreateOption fromImage -VM $VM -Caching ReadWrite -DiskSizeInGB 128 -Name "$VMName-OSDisk" -Windows
$VM = Set-AzureRmVMBootDiagnostics -Enable -ResourceGroupName $resourcegroupname -VM $VM -StorageAccountName $diagstorageacc

#Create the VM

New-AzureRmVM -Location $location -ResourceGroupName $resourcegroupname -VM $VM -Verbose

#Joining the VM into the domain
Set-AzureRmVMADDomainExtension -DomainName $FQDNDomain -ResourceGroupName $resourcegroupname -VMName $VMName -Credential $DomainCredential -OUPath $OUPathWEBAPP -Location $location -JoinOption 3 -Restart -Verbose
}
else
{
write-Host "The Azure VM $VMName Already Exist"
}

                                        }

#########################
#   APP VM SETTINGS     #
#########################

For ($i=1; $i -le $APPVMumber; $i++) {

# VM Information #

$itemNumber = "$i"
$VMName = "$convname"+"APP"+"$itemNumber"

Get-AzureRMVM -Name $VMName -ResourceGroupName $resourcegroupname  -ErrorVariable notPresent -ErrorAction SilentlyContinue |Out-Null
if ($notPresent)
{
write-Host "DEPLOYING: The New Azure VM $VMName"
# Networking #

$VNET = Get-AzureRmVirtualNetwork -Name $vnetname -ResourceGroupName $resourcegroupname
$NICName01 = $VMName + "-NIC1"
$TarSubnet01 = Get-AzureRmVirtualNetworkSubnetConfig -VirtualNetwork $VNET -Name $subnetname
$NIC01 = New-AzureRmNetworkInterface -Location $location -Name $NICName01 -ResourceGroupName $resourcegroupname -SubnetId $TarSubnet01.Id

# VM PROFILE #

$VM = New-AzureRmVMConfig -VMName $VMName -VMSize $VMSizeAPP -LicenseType "Windows_Server"
$VM = Add-AzureRmVMNetworkInterface -Id $NIC01.Id -VM $VM -Primary
$VM = Set-AzureRmVMSourceImage -Offer $OfferNameWS -PublisherName $PubNameWS -Skus $SkuNameWS -Version $VersionWS -VM $VM
$VM = Set-AzureRmVMOperatingSystem -ComputerName $VMName -Credential $LocalCredential -VM $VM -Windows -EnableAutoUpdate -ProvisionVMAgent -TimeZone $TimeZone
$VM = Set-AzureRmVMOSDisk -CreateOption fromImage -VM $VM -Caching ReadWrite -DiskSizeInGB 128 -Name "$VMName-OSDisk" -Windows
$VM = Set-AzureRmVMBootDiagnostics -Enable -ResourceGroupName $resourcegroupname -VM $VM -StorageAccountName $diagstorageacc

#Create the VM

New-AzureRmVM -Location $location -ResourceGroupName $resourcegroupname -VM $VM -Verbose

#Joining the VM into the domain
Set-AzureRmVMADDomainExtension -DomainName $FQDNDomain -ResourceGroupName $resourcegroupname -VMName $VMName -Credential $DomainCredential -OUPath $OUPathAPP -Location $location -JoinOption 3 -Restart -Verbose
}
else
{
write-Host "The Azure VM $VMName Already Exist"
}

                                }

#########################
#REDIS LINUX VM SETTINGS#
#########################

For ($i=1; $i -le $REDISVMNumber; $i++) {

# VM Information #

$itemNumber = "$i"
$VMName = "$convname"+"RD"+"$itemNumber"


Get-AzureRMVM -Name $VMName -ResourceGroupName $resourcegroupname  -ErrorVariable notPresent -ErrorAction SilentlyContinue |Out-Null
if ($notPresent)
{
write-Host "DEPLOYING: The New Azure VM $VMName"
# Networking #

$VNET = Get-AzureRmVirtualNetwork -Name $vnetname -ResourceGroupName $resourcegroupname
$NICName01 = $VMName + "-NIC1"
$TarSubnet01 = Get-AzureRmVirtualNetworkSubnetConfig -VirtualNetwork $VNET -Name $subnetname
$NIC01 = New-AzureRmNetworkInterface -Location $location -Name $NICName01 -ResourceGroupName $resourcegroupname -SubnetId $TarSubnet01.Id

# VM PROFILE #

$VM = New-AzureRmVMConfig -VMName $VMName -VMSize $VMSizeLX
$VM = Add-AzureRmVMNetworkInterface -Id $NIC01.Id -VM $VM -Primary
$VM = Set-AzureRmVMSourceImage -Offer $OfferNameLX -PublisherName $PubNameLX -Skus $SkuNameLX -Version $VersionLX -VM $VM
$VM = Set-AzureRmVMOperatingSystem -ComputerName $VMName -Credential $LocalCredential -VM $VM -Linux
$VM = Set-AzureRmVMOSDisk -CreateOption fromImage -VM $VM -Caching ReadWrite -DiskSizeInGB 128 -Name "$VMName-OSDisk" -Linux
$VM = Set-AzureRmVMBootDiagnostics -Enable -ResourceGroupName $resourcegroupname -VM $VM -StorageAccountName $diagstorageacc

#Create the VM

New-AzureRmVM -Location $location -ResourceGroupName $resourcegroupname -VM $VM -Verbose

#Create Users and add on the Sudo group
$ScriptSettings = @{"fileUris" = @($filelinux); "commandToExecute" = "./$fileNamelinux $defaultpass $username $usernamenumber";}
Set-AzureRmVMExtension -Publisher "Microsoft.Azure.Extensions" -ExtensionType "customscript" -Settings $ScriptSettings -ResourceGroupName $resourcegroupname -VMName $VMName -Name "addusers" -TypeHandlerVersion '2.0' -Location $location
}
else
{
write-Host "The Azure VM $VMName Already Exist"
}

                                            }


############################
# REMOTESERVER VM SETTINGS #
############################

# VM Information #

$itemNumber = "1"
$VMName = "$convname"+"RS"+"$itemNumber"

Get-AzureRMVM -Name $VMName -ResourceGroupName $resourcegroupname  -ErrorVariable notPresent -ErrorAction SilentlyContinue |Out-Null
if ($notPresent)
{
write-Host "DEPLOYING: The New Azure VM $VMName"
# Networking #
$publicipadress = New-AzureRmPublicIpAddress -Name $publicipname -ResourceGroupName $resourcegroupname -Location $location -IpAddressVersion IPv4 -AllocationMethod Dynamic -DomainNameLabel $rdsname

$VNET = Get-AzureRmVirtualNetwork -Name $vnetname -ResourceGroupName $resourcegroupname
$NICName01 = $VMName + "-NIC1"
$TarSubnet01 = Get-AzureRmVirtualNetworkSubnetConfig -VirtualNetwork $VNET -Name $subnetname
$NIC01 = New-AzureRmNetworkInterface -Location $location -Name $NICName01 -ResourceGroupName $resourcegroupname -SubnetId $TarSubnet01.Id -PrivateIpAddress $remoteserverip -PublicIpAddressId $publicipadress.Id

# VM PROFILE #

$VM = New-AzureRmVMConfig -VMName $VMName -VMSize $VMSizeRDS -LicenseType "Windows_Server"
$VM = Add-AzureRmVMNetworkInterface -Id $NIC01.Id -VM $VM -Primary
$VM = Set-AzureRmVMSourceImage -Offer $OfferNameWS -PublisherName $PubNameWS -Skus $SkuNameWS -Version $VersionWS -VM $VM
$VM = Set-AzureRmVMOperatingSystem -ComputerName $VMName -Credential $LocalCredential -VM $VM -Windows -EnableAutoUpdate -ProvisionVMAgent -TimeZone $TimeZone
$VM = Set-AzureRmVMOSDisk -CreateOption fromImage -VM $VM -Caching ReadWrite -DiskSizeInGB 128 -Name "$VMName-OSDisk" -Windows
$VM = Set-AzureRmVMBootDiagnostics -Enable -ResourceGroupName $resourcegroupname -VM $VM -StorageAccountName $diagstorageacc

#Create the VM

New-AzureRmVM -Location $location -ResourceGroupName $resourcegroupname -VM $VM -Verbose

#Joining the VM into the domain
Set-AzureRmVMADDomainExtension -DomainName $FQDNDomain -ResourceGroupName $resourcegroupname -VMName $VMName -Credential $DomainCredential -OUPath $OUPath -Location $location -JoinOption 3 -Restart -Verbose

#Install RDS service and Software necessary as Notepad+=, Redis Manager, Putty and WinSCP
Set-AzureRmVMCustomScriptExtension -Location $location -Name "rds" -VMName $VMName -ResourceGroupName $resourcegroupname -StorageAccountName $storageaccountname  -StorageAccountKey $storageAccountKey -ContainerName $storageContainer -FileName $fileNamerds -Run $fileNamerds
}
else
{
write-Host "The Azure VM $VMName Already Exist"
}

#########################
#    DB  VM SETTINGS   #
#########################
For ($i=1; $i -le $SQLVMumber; $i++) {

# VM Information #

$itemNumber = "$i"
$VMName = "$convname"+"DB"+"$itemNumber"

$AGDatabase = Get-AzureRmAvailabilitySet -ResourceGroupName $resourcegroupname -Name ("$convname" + "-AS")

Get-AzureRMVM -Name $VMName -ResourceGroupName $resourcegroupname  -ErrorVariable notPresent -ErrorAction SilentlyContinue |Out-Null
if ($notPresent)
{
write-Host "DEPLOYING: The New Azure VM $VMName"
# Networking #

$VNET = Get-AzureRmVirtualNetwork -Name $vnetname -ResourceGroupName $resourcegroupname
$NICName01 = $VMName + "-NIC1"
$TarSubnet01 = Get-AzureRmVirtualNetworkSubnetConfig -VirtualNetwork $VNET -Name $subnetname
$NIC01 = New-AzureRmNetworkInterface -Location $location -Name $NICName01 -ResourceGroupName $resourcegroupname -SubnetId $TarSubnet01.Id

# VM PROFILE #

$VM = New-AzureRmVMConfig -VMName $VMName -VMSize $VMSizeDB -LicenseType "Windows_Server" -AvailabilitySetId $AGDatabase.Id
$VM = Add-AzureRmVMNetworkInterface -Id $NIC01.Id -VM $VM -Primary
$VM = Set-AzureRmVMSourceImage -Offer $OfferNameDB -PublisherName $PubNameDB -Skus $SkuNameDB -Version $Version -VM $VM
$VM = Set-AzureRmVMOperatingSystem -ComputerName $VMName -Credential $LocalCredential -VM $VM -Windows -EnableAutoUpdate -ProvisionVMAgent -TimeZone $TimeZone
$VM = Set-AzureRmVMOSDisk -CreateOption fromImage -VM $VM -Caching ReadWrite -DiskSizeInGB 128 -Name "$VMName-OSDisk" -Windows
$VM = Add-AzureRmVMDataDisk -CreateOption Empty -Lun 01 -VM $VM -Caching ReadOnly -DiskSizeInGB 128 -Name "$VMName-Data"
$VM = Set-AzureRmVMBootDiagnostics -Enable -ResourceGroupName $resourcegroupname -VM $VM -StorageAccountName $diagstorageacc

#Create the VM

New-AzureRmVM -Location $location -ResourceGroupName $resourcegroupname -VM $VM -Verbose

#Joining the VM into the domain
Set-AzureRmVMADDomainExtension -DomainName $FQDNDomain -ResourceGroupName $resourcegroupname -VMName $VMName -Credential $DomainCredential -OUPath $OUPath -Location $location -JoinOption 3 -Restart -Verbose

#create SQL account and enable mixed mode#
Set-AzureRmVMCustomScriptExtension -Name "SetSqlServerConfig" -VMName $VMName -ResourceGroupName $resourcegroupname -Location $location -StorageAccountName $storageaccountname -ContainerName $storageContainer -FileName $fileNamesql `
        -Argument "-VmAdminUsername $LocalAdmin -VmAdminPassword $GetPassword -SqlLoginUsername $SqlLoginUsername -SqlLoginPassword $SqlLoginPassword -SvcSecusername $SvcSecusername -SvcSecPassword $SvcSecPassword"
}
else
{
write-Host "The Azure VM $VMName Already Exist"
}


                                            }



#########################
#   BI DB VM SETTINGS   #
#########################
For ($i=1; $i -le $BISQLVMnumber; $i++) { 

# VM Information #

$itemNumber = "$i"
$VMName = "$convname"+"DB"+"$itemNumber"

Get-AzureRMVM -Name $VMName -ResourceGroupName $resourcegroupname  -ErrorVariable notPresent -ErrorAction SilentlyContinue |Out-Null
if ($notPresent)
{
write-Host "DEPLOYING: The New Azure VM $VMName"
# Networking #

$VNET = Get-AzureRmVirtualNetwork -Name $vnetname -ResourceGroupName $resourcegroupname
$NICName01 = $VMName + "-NIC1"
$TarSubnet01 = Get-AzureRmVirtualNetworkSubnetConfig -VirtualNetwork $VNET -Name $subnetname
$NIC01 = New-AzureRmNetworkInterface -Location $location -Name $NICName01 -ResourceGroupName $resourcegroupname -SubnetId $TarSubnet01.Id

# VM PROFILE #

$VM = New-AzureRmVMConfig -VMName $VMName -VMSize $VMSizeDB -LicenseType "Windows_Server"
$VM = Add-AzureRmVMNetworkInterface -Id $NIC01.Id -VM $VM -Primary
$VM = Set-AzureRmVMSourceImage -Offer $OfferNameDB -PublisherName $PubNameDB -Skus $SkuNameDB -Version $VersionDB -VM $VM
$VM = Set-AzureRmVMOperatingSystem -ComputerName $VMName -Credential $LocalCredential -VM $VM -Windows -EnableAutoUpdate -ProvisionVMAgent -TimeZone $TimeZone
$VM = Set-AzureRmVMOSDisk -CreateOption fromImage -VM $VM -Caching ReadWrite -DiskSizeInGB 128 -Name "$VMName-OSDisk" -Windows
$VM = Add-AzureRmVMDataDisk -CreateOption Empty -Lun 01 -VM $VM -Caching ReadOnly -DiskSizeInGB 128 -Name "$VMName-Data"
$VM = Set-AzureRmVMBootDiagnostics -Enable -ResourceGroupName $resourcegroupname -VM $VM -StorageAccountName $diagstorageacc

#Create the VM

New-AzureRmVM -Location $location -ResourceGroupName $resourcegroupname -VM $VM -Verbose

#Joining the VM into the domain
Set-AzureRmVMADDomainExtension -DomainName $FQDNDomain -ResourceGroupName $resourcegroupname -VMName $VMName -Credential $DomainCredential -OUPath $OUPath -Location $location -JoinOption 3 -Restart -Verbose

#create SQL account and enable mixed mode#
Set-AzureRmVMCustomScriptExtension -Name "SetSqlServerConfig" -VMName $VMName -ResourceGroupName $resourcegroupname -Location $location -StorageAccountName $storageaccountname -ContainerName $storageContainer -FileName $fileNamesql `
        -Argument "-VmAdminUsername $LocalAdmin -VmAdminPassword $GetPassword -SqlLoginUsername $SqlLoginUsername -SqlLoginPassword $SqlLoginPassword -SvcSecusername $SvcSecusername -SvcSecPassword $SvcSecPassword"
}
else
{
write-Host "The Azure VM $VMName Already Exist"
}

                                               }



#########################
#LOAD BALANCE SETTINGS  #
#########################

Get-AzureRmLoadBalancer -ResourceGroupName $resourcegroupname -Name $LBDatabase -ErrorVariable notPresent -ErrorAction SilentlyContinue |Out-Null
if ($notPresent)
{
write-Host "DEPLOYING: The Load Balancer $LBDatabase"
$probeReport = New-AzureRmLoadBalancerProbeConfig -Name "TRReportEndPointProbe" -Protocol TCP -Port 59997 -IntervalInSeconds 5 -ProbeCount 3
$probeSQL = New-AzureRmLoadBalancerProbeConfig -Name "TRSQLEndPointProbe" -Protocol TCP -Port 59996 -IntervalInSeconds 5 -ProbeCount 3
$frontendIPaddressApp = New-AzureRmLoadBalancerFrontendIpConfig -Name "LoadBalancerFrontEnd" -PrivateIpAddress $LBIp -Subnetid "/subscriptions/$subscription/resourceGroups/$resourcegroupname/providers/Microsoft.Network/virtualNetworks/$vnetname/subnets/$subnetname"
$frontendIPaddressReport = New-AzureRmLoadBalancerFrontendIpConfig -Name "TRReportAGLST" -PrivateIpAddress $LBIpReport -Subnetid "/subscriptions/$subscription/resourceGroups/$resourcegroupname/providers/Microsoft.Network/virtualNetworks/$vnetname/subnets/$subnetname"
$backendPool = New-AzureRmLoadBalancerBackendAddressPoolConfig -Name "TRLBBackendPool"
$backendPoolreport = New-AzureRmLoadBalancerBackendAddressPoolConfig -Name "TRReportLSTBackEnd"
$LBRuleSQL = New-AzureRmLoadBalancerRuleConfig -Name "TRSQLEndPointRule" -FrontendIpConfiguration $frontendIPaddressApp -FrontendPort 1433 -Protocol Tcp -BackendAddressPool $backendPool -BackendPort 1433 -Probe $probeSQL -EnableFloatingIP -IdleTimeoutInMinutes 4
$LBRuleReport = New-AzureRmLoadBalancerRuleConfig -Name "TRReportEndPointRule" -FrontendIpConfiguration $frontendIPaddressReport -FrontendPort 1433 -Protocol Tcp -BackendAddressPool $backendPoolreport -BackendPort 1433 -Probe $probeReport -EnableFloatingIP -IdleTimeoutInMinutes 4
 
New-AzureRmLoadBalancer -ResourceGroupName $resourcegroupname -Name $LBDatabase -Sku Basic `
                                        -Location $location -FrontendIpConfiguration $frontendIPaddressApp,$frontendIPaddressReport  `
                                        -BackendAddressPool $backendPool,$backendPoolreport -Probe $probeReport, $probeSQL `
                                        -LoadBalancingRule $LBRuleSQL, $LBRuleReport |Out-Null

}
else
{
write-Host "The Load Balancer $LBDatabase Already Exist"
}


pause


