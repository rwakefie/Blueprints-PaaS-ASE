#Parameters
[CmdletBinding()]
Param (
    [object]$WebhookData
)
$VerbosePreference = 'continue'

if ($WebHookData){

    # Collect properties of WebhookData
    $WebhookName     =     $WebHookData.WebhookName
    $WebhookBody     =     $WebHookData.RequestBody

    # Collect individual headers. Input converted from JSON.
    $Input = (ConvertFrom-Json -InputObject $WebhookBody)
    Write-Verbose "WebhookBody: $Input"
    Write-Output -InputObject ('Runbook started from webhook' -f $WebhookName)
}
$SystemPrefixName = $Input.SystemPrefixName
$vnetAddressPrefix = $Input.vnetAddressPrefix
$vnetAddressPrefixCIDR = $Input.vnetAddressPrefixCIDR
$WAFSubnetPrefix = $Input.WAFSubnetPrefix
$WAFSubnetPrefixCIDR = $Input.WAFSubnetPrefixCIDR
$WebAppSubnetPrefix = $Input.WebAppSubnetPrefix
$WebAppSubnetPrefixCIDR = $Input.WebAppSubnetPrefixCIDR
$APIAppSubnetPrefix = $Input.APIAppSubnetPrefix
$APIAppSubnetPrefixCIDR = $Input.APIAppSubnetPrefixCIDR
$RedisCacheSubnetPrefix = $Input.RedisCacheSubnetPrefix
$RedisCacheSubnetPrefixCIDR = $Input.RedisCacheSubnetPrefixCIDR
#$customDNSIP = $Input.customDNSIP
#$dnsOption = $Input.dnsOption
$redisShardCount = $Input.redisShardCount
$redisCacheCapacity = $Input.redisCacheCapacity
$appServicePlanNameWeb = $Input.appServicePlanNameWeb
#$appServicePlanNameApi = $Input.appServicePlanNameApi
$ApiDNS = $Input.ApiDNS
$WebDNS = $Input.WebDNS
$internalLoadBalancingMode = $Input.internalLoadBalancingMode
$frontEndSize = $Input.frontEndSize
$frontEndCount = $Input.frontEndCount
$workerPoolOneInstanceSize = $Input.workerPoolOneInstanceSize
$workerPoolOneInstanceCount = $Input.workerPoolOneInstanceCount
$workerPoolTwoInstanceSize = $Input.workerPoolTwoInstanceSize
$workerPoolTwoInstanceCount = $Input.workerPoolTwoInstanceCount
$workerPoolThreeInstanceSize = $Input.workerPoolThreeInstanceSize
$workerPoolThreeInstanceCount = $Input.workerPoolThreeInstanceCount
$numberOfWorkersFromWorkerPool = $Input.numberOfWorkersFromWorkerPool
$workerPool  = $Input.workerPool
$applicationGatewaySize = $Input.applicationGatewaySize
$wafEnabled = $Input.wafEnabled
$WafCapacity = $Input.WafCapacity
$databaseServiceObjectiveName = $Input.databaseServiceObjectiveName
$databaseEdition = $Input.databaseEdition
$sqlAdministratorLogin = $Input.sqlAdministratorLogin

#Module Handling
$HRW = (test-path "C:\Program Files\Microsoft Monitoring Agent\Agent\AzureAutomation")
If ($HRW -eq $true) {
    Write-Output "Running on HRW"
    #Download Modules
    $SWPassModuleExist = (Test-Path "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\New-SWRandomPassword")
    If ($SWPassModuleExist -eq $False) {
    $SWPassModuleURI = "https://raw.github.com/rwakefie/AutomationStuff/master/Modules/New-SWRandomPassword.zip"
    Invoke-WebRequest -Uri $SWPassModuleURI -OutFile "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\New-SWRandomPassword.zip"
    Expand-Archive -LiteralPath "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\New-SWRandomPassword.zip" -DestinationPath "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\" -Force
    }

    $RESTAPIModuleExist = (Test-Path "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\New-AzureRestAuthorizationHeader")
    If ($RESTAPIModuleExist -eq $False) {
    $RESTAPIModuleURI = "https://raw.github.com/rwakefie/AutomationStuff/master/Modules/New-AzureRestAuthorizationHeader.zip"
    Invoke-WebRequest -Uri $RESTAPIModuleURI -OutFile "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\New-AzureRestAuthorizationHeader.zip"
    Expand-Archive -LiteralPath "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\New-AzureRestAuthorizationHeader.zip" -DestinationPath "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\" -Force
    }

    #Load modules
    Import-Module New-SWRandomPassword
    Import-Module New-AzureRestAuthorizationHeader
    Install-Module AzureAD
    Install-Module AzureRM
}

Else {
    Write-Output "Running in Azure"
    #Load Modules
    Import-Module New-SWRandomPassword
    Import-Module New-AzureRestAuthorizationHeader
    Import-Module AzureAD
    Import-Module AzureRM
}

#Install ADAL for REST API
$DLL = Test-Path "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
$DLL2 = Test-Path "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll"
If ($DLL -eq $false) {

Write-Output "Required files not present, installing..."

$WebPiURL = "https://download.microsoft.com/download/C/F/F/CFF3A0B8-99D4-41A2-AE1A-496C08BEB904/WebPlatformInstaller_amd64_en-US.msi"
Invoke-WebRequest -Uri $WebPiURL -OutFile $env:TEMP\WebPlatformInstaller_amd64_en-US.msi

Start-Process msiexec -ArgumentList @("/i $env:TEMP\WebPlatformInstaller_amd64_en-US.msi", "/quiet", "/norestart") -Wait

$WebPiCMD = "$env:ProgramFiles\Microsoft\Web Platform Installer\"
Start-Process $WebPiCMD\WebpiCmd.exe -ArgumentList @("/install", "/products:WindowsAzurePowershell", "/AcceptEula") -wait

}

If ((Test-Path "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.dll") -eq $True) {
    Write-Output "Microsoft.IdentityModel.Clients.ActiveDirectory.dll is Present"
    } 
Else {
    Write-Output "Microsoft.IdentityModel.Clients.ActiveDirectory.dll is still missing"
    }

If ((Test-Path "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll") -eq $True) {
    Write-Output "Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll is Present"
    } 
Else {
    Write-Output "Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll is still missing" 
    }

#Download ASEB repo
$Location = $env:TEMP
$url = "https://github.com/mayurshintre/Blueprints-PaaS-ASE/archive/master.zip"
$output = "$Location\master.zip"
Invoke-WebRequest -Uri $url -OutFile $Output

#Extract zip file
Expand-Archive -LiteralPath $output -DestinationPath $location
$Scripts = "$Location\Blueprints-PaaS-ASE-master\ase-ilb-blueprint"
$JSONParams = "$Scripts\azuredeploy.parameters.json" 

#Variables for testing without webhook, remove when done testing
$SystemPrefixName = "ASEB"
$vnetAddressPrefix = "10.0.0.0"
$vnetAddressPrefixCIDR = 16
$WAFSubnetPrefix = "10.0.0.0"
$WAFSubnetPrefixCIDR = 27
$WebAppSubnetPrefix = "10.0.1.0"
$WebAppSubnetPrefixCIDR = 26
#$APIAppSubnetPrefix = "10.0.2.0"
#$APIAppSubnetPrefixCIDR = 26
$RedisCacheSubnetPrefix = "10.0.3.0"
$RedisCacheSubnetPrefixCIDR = 27
#$customDNSIP = "10.0.0.4"
#$dnsOption = "customdns"
$redisShardCount = 2
$redisCacheCapacity = 1
$appServicePlanNameWeb = "ASPNameWeb"
#$appServicePlanNameApi = "ASPNameApi"
#$ApiDNS = "Api.demo"
$WebDNS = "Web.demo"
$internalLoadBalancingMode = 1
$frontEndSize = "Medium"
$frontEndCount = 2
$workerPoolOneInstanceSize = "Small"
$workerPoolOneInstanceCount = 2
$workerPoolTwoInstanceSize = "Small"
$workerPoolTwoInstanceCount = 2
$workerPoolThreeInstanceSize = "Small"
$workerPoolThreeInstanceCount = 0
$numberOfWorkersFromWorkerPool = 2
$workerPool  = "WP1"
$applicationGatewaySize = "WAF_Medium"
$wafEnabled = $true
$WafCapacity = 2
$databaseServiceObjectiveName = "Basic"
$databaseEdition = "Basic"
$sqlAdministratorLogin = "Master"

#JSON Description
$SystemPrefixNameDesc = "String to append to all resource names"
$vnetAddressPrefixDesc = "IP Address Of Virtual Network Without CIDR"
$vnetAddressPrefixCIDRDesc = "Virtual Network CIDR Block"
$WAFSubnetPrefixDesc ="WAF Subnet IP Address Without CIDR Block"
$WAFSubnetPrefixCIDRDesc = "WAF Subnet CIDR Block"
$WebAppSubnetPrefixDesc = "Web App Subnet IP Address Without CIDR Block"
$WebAppSubnetPrefixCIDRDesc = "Web App Subnet CIDR Block"
#$APIAppSubnetPrefixDesc = "API App Subnet IP Address Without CIDR Block"
#$APIAppSubnetPrefixCIDRDesc = "API App Subnet CIDR Block"
#$APIAppSubnetPrefixCIDRDesc = "API App Subnet CIDR Block"
$RedisCacheSubnetPrefixDesc = "Redis Cache Subnet IP Address Without CIDR Block"
$RedisCacheSubnetPrefixDesc = "Redis Cache Subnet IP Address Without CIDR Block"
$RedisCacheSubnetPrefixCIDRDesc = "Redis Cache Subnet CIDR Block"
#$customDNSIPDesc = "IP Address of Custom DNS Server"
#$dnsOptionDesc = "This will set a custom DNS server or use Azure Fabric DNS (not Azure DNS service). Pick either azuredns or customdns. This is Case Sensitive."
$redisShardCountDesc = "Number of highly available shards to create in the cluster. Requires Premium SKU. Set to 0 to not set up clustering."
$redisCacheCapacityDesc = "The size of the new Azure Redis Cache instance. Valid family and capacity combinations are (C0..C6, P1..P4)."
$appServicePlanNameWebDesc = "The name of the App Service plan to use for hosting the web app."
#$appServicePlanNameApiDesc = "The name of the App Service plan to use for hosting the web app."
#$ApiDNSDesc = "Set to the root internal domain name to associate with this ASP."
$WebDNSDesc = "Set this to the root domain associated with the Web App."
$internalLoadBalancingModeDesc = "0 = public VIP only, 1 = only ports 80/443 are mapped to ILB VIP, 2 = only FTP ports are mapped to ILB VIP, 3 = both ports 80/443 and FTP ports are mapped to an ILB VIP."
$frontEndSizeDesc = "Instance size for the front-end pool.  Maps to P2,P3,P4."
$frontEndCountDesc = "Number of instances in the front-end pool.  Minimum of two."
$workerPoolOneInstanceSizeDesc = "Instance size for worker pool one.  Maps to P1,P2,P3,P4."
$workerPoolOneInstanceCountDesc = "Number of instances in worker pool one.  Minimum of two."
$workerPoolTwoInstanceSizeDesc = "Instance size for worker pool two.  Maps to P1,P2,P3,P4."
$workerPoolTwoInstanceCountDesc = "Number of instances in worker pool two.  Can be zero if not using worker pool two."
$workerPoolThreeInstanceSizeDesc = "Instance size for worker pool three.  Maps to P1,P2,P3,P4."
$workerPoolThreeInstanceCountDesc = "Number of instances in worker pool three.  Can be zero if not using worker pool three."
$numberOfWorkersFromWorkerPoolDesc = "Defines the number of workers from the worker pool that will be used by the app service plan."
$workerPoolDesc = "Defines which worker pool's (WP1, WP2 or WP3) resources will be used for the app service plan."
$applicationGatewaySizeDesc = "WAF Appliaction Gateway Size"
$wafEnabledDesc = "WAF Enabled"
$WafCapacityDesc = "Number of WAF Instances"
$databaseServiceObjectiveNameDesc = "The name of the configured Service Level Objective of the Azure SQL database. This is the Service Level Objective that is in the process of being applied to the Azure SQL database."
$databaseEditionDesc = "The edition of the Azure SQL database. The DatabaseEditions enumeration contains all the valid editions."
$sqlAdministratorLoginDesc = "Login name for SQL"


#Modify JSON with correct parameters
$JSON = Get-Content $JSONParams -RAW | ConvertFrom-Json
$JSON.parameters.SystemPrefixName.value=$SystemPrefixName
$JSON.parameters.SystemPrefixName.metadata.description=$SystemPrefixNameDesc
#$JSON.parameters.APIAppSubnetPrefix.value=$APIAppSubnetPrefix
#$JSON.parameters.APIAppSubnetPrefix.metadata.description=$APIAppSubnetPrefixDesc
#$JSON.parameters.APIAppSubnetPrefixCIDR.value=$APIAppSubnetPrefixCIDR
#$JSON.parameters.APIAppSubnetPrefixCIDR.metadata.description=$APIAppSubnetPrefixCIDRDesc
#$JSON.parameters.ApiDNS.value=$ApiDNS
#$JSON.parameters.ApiDNS.metadata.description=$ApiDNSDesc
$JSON.parameters.applicationGatewaySize.value=$applicationGatewaySize
$JSON.parameters.applicationGatewaySize.metadata.description=$applicationGatewaySizeDesc
#$JSON.parameters.appServicePlanNameApi.value=$appServicePlanNameApi
#$JSON.parameters.appServicePlanNameApi.metadata.description=$appServicePlanNameApiDesc
$JSON.parameters.appServicePlanNameWeb.value=$appServicePlanNameWeb
$JSON.parameters.appServicePlanNameWeb.metadata.description=$appServicePlanNameWebDesc
#$JSON.parameters.customDNSIP.value=$customDNSIP
#$JSON.parameters.customDNSIP.metadata.description=$customDNSIPDesc
#$JSON.parameters.dnsOption.value=$dnsOption
#$JSON.parameters.dnsOption.metadata.description=$dnsOptionDesc
$JSON.parameters.frontEndCount.value=$frontEndCount
$JSON.parameters.frontEndCount.metadata.description=$frontEndCountDesc
$JSON.parameters.frontEndSize.value=$frontEndSize
$JSON.parameters.frontEndSize.metadata.description=$frontEndSizeDesc
$JSON.parameters.internalLoadBalancingMode.value=$internalLoadBalancingMode
$JSON.parameters.internalLoadBalancingMode.metadata.description=$internalLoadBalancingModeDesc
$JSON.parameters.numberOfWorkersFromWorkerPool.value=$numberOfWorkersFromWorkerPool
$JSON.parameters.numberOfWorkersFromWorkerPool.metadata.description=$numberOfWorkersFromWorkerPoolDesc
$JSON.parameters.redisCacheCapacity.value=$redisCacheCapacity
$JSON.parameters.redisCacheCapacity.metadata.description=$redisCacheCapacityDesc
$JSON.parameters.RedisCacheSubnetPrefix.value=$RedisCacheSubnetPrefix
$JSON.parameters.RedisCacheSubnetPrefix.metadata.description=$RedisCacheSubnetPrefixDesc
$JSON.parameters.redisShardCount.value=$redisShardCount
$JSON.parameters.redisShardCount.metadata.description=$redisShardCountDesc
$JSON.parameters.sqlAdministratorLogin.value=$sqlAdministratorLogin
$JSON.parameters.sqlAdministratorLogin.metadata.description=$sqlAdministratorLoginDesc
$JSON.parameters.vnetAddressPrefix.value=$vnetAddressPrefix
$JSON.parameters.vnetAddressPrefix.metadata.description=$vnetAddressPrefixDesc
$JSON.parameters.vnetAddressPrefixCIDR.value=$vnetAddressPrefixCIDR
$JSON.parameters.vnetAddressPrefixCIDR.metadata.description=$vnetAddressPrefixCIDRDesc
$JSON.parameters.WebAppSubnetPrefix.value=$WebAppSubnetPrefix
$JSON.parameters.WebAppSubnetPrefix.metadata.description=$WebAppSubnetPrefixDesc
$JSON.parameters.WafCapacity.value=$WafCapacity
$JSON.parameters.WafCapacity.metadata.description=$WafCapacityDesc
$JSON.parameters.wafEnabled.value=$wafEnabled
$JSON.parameters.wafEnabled.metadata.description=$wafEnabledDesc
$JSON.parameters.WAFSubnetPrefixCIDR.value=$WAFSubnetPrefixCIDR
$JSON.parameters.WAFSubnetPrefixCIDR.metadata.description=$WAFSubnetPrefixCIDRDesc
$JSON.parameters.WebAppSubnetPrefix.value=$WebAppSubnetPrefix
$JSON.parameters.WebAppSubnetPrefix.metadata.description=$WebAppSubnetPrefixDesc
$JSON.parameters.WebAppSubnetPrefixCIDR.value=$WebAppSubnetPrefixCIDR
$JSON.parameters.WebAppSubnetPrefixCIDR.metadata.description=$WebAppSubnetPrefixCIDRDesc
$JSON.parameters.WebDNS.value=$WebDNS
$JSON.parameters.WebDNS.metadata.description=$WebDNSDesc
$JSON.parameters.workerPool.value=$workerPool
$JSON.parameters.workerPool.metadata.description=$workerPoolDesc
$JSON.parameters.workerPoolOneInstanceCount.value=$workerPoolOneInstanceCount
$JSON.parameters.workerPoolOneInstanceCount.metadata.description=$workerPoolOneInstanceCountDesc
$JSON.parameters.workerPoolOneInstanceSize.value=$workerPoolOneInstanceSize
$JSON.parameters.workerPoolOneInstanceSize.metadata.description=$workerPoolOneInstanceSizeDesc
$JSON.parameters.workerPoolThreeInstanceCount.value=$workerPoolThreeInstanceCount
$JSON.parameters.workerPoolThreeInstanceCount.metadata.description=$workerPoolThreeInstanceCountDesc
$JSON.parameters.workerPoolThreeInstanceSize.value=$workerPoolThreeInstanceSize
$JSON.parameters.workerPoolThreeInstanceSize.metadata.description=$workerPoolThreeInstanceSizeDesc
$JSON.parameters.workerPoolTwoInstanceCount.value=$workerPoolTwoInstanceCount
$JSON.parameters.workerPoolTwoInstanceCount.metadata.description=$workerPoolTwoInstanceCountDesc
$JSON.parameters.workerPoolTwoInstanceSize.value=$workerPoolTwoInstanceSize
$JSON.parameters.workerPoolTwoInstanceCount.metadata.description=$workerPoolTwoInstanceSizeDesc
$JSON.parameters.databaseServiceObjectiveName.value=$databaseServiceObjectiveName
$JSON.parameters.databaseServiceObjectiveName.metadata.description=$databaseServiceObjectiveNameDesc
$JSON.parameters.databaseEdition.value=$databaseEdition
$JSON.parameters.databaseEdition.metadata.description=$databaseEditionDesc
#Save JSON file
$JSON | ConvertTo-Json -Depth 3 | set-content $JSONParams

#Output parameters to console
Write-Output "SystemPrefixName $SystemPrefixName"
Write-Output "vnetAddressPrefix $vnetAddressPrefix"
Write-Output "vnetAddressPrefixCIDR $vnetAddressPrefixCIDR"
Write-Output "WAFSubnetPrefix $WAFSubnetPrefix"
Write-Output "WAFSubnetPrefixCIDR $WAFSubnetPrefixCIDR"
Write-Output "WebAppSubnetPrefix $WebAppSubnetPrefix"
Write-Output "WebAppSubnetPrefixCIDR $WebAppSubnetPrefixCIDR"
#Write-Output "APIAppSubnetPrefix $APIAppSubnetPrefix"
#Write-Output "APIAppSubnetPrefixCIDR $APIAppSubnetPrefixCIDR"
Write-Output "RedisCacheSubnetPrefix $RedisCacheSubnetPrefix"
Write-Output "RedisCacheSubnetPrefixCIDR $RedisCacheSubnetPrefixCIDR"
#Write-Output "customDNSIP $customDNSIP"
#Write-Output "dnsOption $dnsOption"
Write-Output "redisShardCount $redisShardCount"
Write-Output "redisCacheCapacity $redisCacheCapacity"
Write-Output "appServicePlanNameWeb $appServicePlanNameWeb"
#Write-Output "appServicePlanNameApi $appServicePlanNameApi"
#Write-Output "ApiDNS $ApiDNS"
Write-Output "WebDNS $WebDNS"
Write-Output "internalLoadBalancingMode $internalLoadBalancingMode"
Write-Output "frontEndSize $frontEndSize"
Write-Output "frontEndCount $frontEndCount"
Write-Output "workerPoolOneInstanceSize $workerPoolOneInstanceSize"
Write-Output "workerPoolOneInstanceCount $workerPoolOneInstanceCount"
Write-Output "workerPoolTwoInstanceSize $workerPoolTwoInstanceSize"
Write-Output "workerPoolTwoInstanceCount $workerPoolTwoInstanceCount"
Write-Output "workerPoolThreeInstanceSize $workerPoolThreeInstanceSize"
Write-Output "workerPoolThreeInstanceCount $workerPoolThreeInstanceCount"
Write-Output "numberOfWorkersFromWorkerPool $numberOfWorkersFromWorkerPool"
Write-Output "workerPool  $workerPool"
Write-Output "applicationGatewaySize $applicationGatewaySize"
Write-Output "wafEnabled $wafEnabled"
Write-Output "WafCapacity $WafCapacity"
Write-Output "sqlAdministratorLogin $sqlAdministratorLogin"




###Version: 2.0         ###  
###Author: Jerad Berhow####
###########################

##USER DEFINED
##MAKE CHANGES HERE TO MATCH YOUR ENVIRONMENT
#region
    ##Azure Region to Deploy all resources including the Resource Group
    $Region = Get-AutomationVariable "ASEB-Region"
    ##Name of the Resource Group to deploy
    $RgName = Get-AutomationVariable "ASEB-ResourceGroup"
    ##Name to give the Deployment that will be ran
    $DeploymentName = $RgName +"-ASEB"
    ##Location of the main azuredeploy.json template
    $TemplateUri = Get-AutomationVariable "ASEB-TemplateURI"
    ##Location of the local parameters file
    $ParameterFile = $JSONParams
    ##Subscription ID that will be used to host the resource group
    $SubscriptionID = Get-AutomationVariable "ASEB-SubscriptionID"
    #TenantID used to connect to azure
    $TenantID = Get-AutomationVariable "SubscriptionTenant"
    #Subscription access cred
    $SubscriptionAccessCredential = Get-AutomationPSCredential "AADCred"
    #ClientID and Key for AAD API
    $ClientID = Get-AutomationVariable "ASEB-ClientID"
    $ClientKey = Get-AutomationVariable "ASEB-ClientKey"
#endregion

Write-Host "=> Alright" -ForegroundColor Yellow
Write-Host "=> Booting up . . ." -ForegroundColor Yellow
Write-Host "=> Begin Azure Deployment seaquences..." -ForegroundColor Yellow
Write-Host "=>" -ForegroundColor Yellow
Write-Host "=>" -ForegroundColor Yellow
Write-Host "=> Systems now online." -ForegroundColor Yellow
Write-Host "=>" -ForegroundColor Yellow
Write-Host "=>" -ForegroundColor Yellow
Write-Host "=> Time to Login to ARM if you are not already." -ForegroundColor Yellow

#Authenicating 
Add-AzureRmAccount -Credential $SubscriptionAccessCredential `
                           -SubscriptionID $SubscriptionID `
                           -Tenant $TenantID
Connect-AzureAD -Credential $SubscriptionAccessCredential

# Checking for network resource group, creating if does not exist
Write-Host "=>" -ForegroundColor Yellow
Write-Host "=> Time to make sure the gremlins have not eaten your Resource Group already..." -ForegroundColor Yellow
if (!(Get-AzureRMResourceGroup -Name $RgName -ErrorAction SilentlyContinue))
{
    Write-Host "=>" -ForegroundColor Yellow
    Write-Host "=> Oh No!  They ate it...." -ForegroundColor Yellow
    Write-Host "=> I got this though... Making a new one for you!" -ForegroundColor Yellow
    New-AzureRmResourceGroup -Name $RgName -Location $Region
    Write-Host "=>" -ForegroundColor Yellow
    Write-Host "=> Resource Group $RgName now exists!" -ForegroundColor Yellow
}
else
{
    Write-Host "=>" -ForegroundColor Yellow
    Write-Host "=> Resource Group $RgName already exists." -ForegroundColor Yellow
}

##GeneratePassword
Write-Host "=>" -ForegroundColor Yellow
Write-Host "=> Generating password for PaaS SQL." -ForegroundColor Yellow
$NewPass = New-SWRandomPassword -MinPasswordLength 30 -MaxPasswordLength 30 | ConvertTo-SecureString -AsPlainText -Force

## Deploying the Template
Write-Host "=>" -ForegroundColor Yellow
Write-Host "=> Logging into the Matrix so I can deploy some Nist Compliant Architecture now..." -ForegroundColor Yellow
Write-Host "=> Here we go...." -ForegroundColor Yellow
New-AzureRMResourceGroupDeployment -Name $DeploymentName `
    -ResourceGroupName $RgName `
    -TemplateUri $TemplateUri `
    -TemplateParameterFile $ParameterFile `
    -sqlAdministratorLoginPassword $NewPass `
    -Region $Region `
    -Mode Incremental `
    -Verbose
Write-Host "=>" -ForegroundColor Yellow
Write-Host "=> Man that was tense... Good thing we know some Kung-Fu or those fraggles might have been the end of the road..." -ForegroundColor Yellow

##Get Outputs from Deployment
Write-Host "=>" -ForegroundColor Yellow
Write-Host "=> Retrieving outputs from deployment $DeploymentName." -ForegroundColor Yellow
$AseWebName = (Get-AzureRmResourceGroupDeployment -ResourceGroupName $RgName -Name $DeploymentName).Outputs.aseWebName.Value
$AseApiName = (Get-AzureRmResourceGroupDeployment -ResourceGroupName $RgName -Name $DeploymentName).Outputs.aseApiName.Value

$VnetName = (Get-AzureRmResourceGroupDeployment -ResourceGroupName $RgName -Name $DeploymentName).Outputs.vnetName.Value
$SqlName = (Get-AzureRmResourceGroupDeployment -ResourceGroupName $RgName -Name $DeploymentName).Outputs.sqlName.Value
$AppGWName = (Get-AzureRmResourceGroupDeployment -ResourceGroupName $RgName -Name $DeploymentName).Outputs.appGWName.Value

##Retrieve Resource ID for ASE
$resourceIDWeb = (Get-AzureRmResource | Where-Object -Property resourcename -EQ $AseWebName).resourceID
$resourceIDApi = (Get-AzureRmResource | Where-Object -Property resourcename -EQ $AseApiName).resourceID

#Set Header
$header = New-AzureRestAuthorizationHeader -ClientId $clientId -ClientKey $key -TenantId $tenantId 

##Set URI
$uriweb = "https://management.azure.com$resourceIDWeb/capacities/virtualip?api-version=2015-08-01"
$uriapi = "https://management.azure.com$resourceIDApi/capacities/virtualip?api-version=2015-08-01"

##Set Hostinginfo variable by invoking rest method
$hostingInfoWeb = Invoke-RestMethod -Uri $uriweb -Headers $header -Method get
$hostingInfoApi = Invoke-RestMethod -Uri $uriapi -Headers $header -Method get

##WAF Rules
#region
$WAFRule1 = New-AzureRmNetworkSecurityRuleConfig -Name DenyAllInbound -Description "Deny All Inbound" `
 -Access Deny -Protocol * -Direction Inbound -Priority 500 `
 -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix * `
 -DestinationPortRange *

  $WAFRule2 = New-AzureRmNetworkSecurityRuleConfig -Name HTTPS-In -Description "Allow Inbound HTTPS" `
 -Access Allow -Protocol Tcp -Direction Inbound -Priority 110 `
 -SourceAddressPrefix Internet -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 443

  $WAFRule3 = New-AzureRmNetworkSecurityRuleConfig -Name HTTP-In -Description "Allow Inbound HTTP" `
 -Access Allow -Protocol Tcp -Direction Inbound -Priority 120 `
 -SourceAddressPrefix Internet -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 80
 
   $WAFRule4 = New-AzureRmNetworkSecurityRuleConfig -Name DNS-In -Description "Allow Inbound DNS" `
 -Access Allow -Protocol Tcp -Direction Inbound -Priority 130 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 53

  $WAFRule5 = New-AzureRmNetworkSecurityRuleConfig -Name DenyAllOutbound -Description "Deny All Outbound" `
 -Access Deny -Protocol * -Direction Outbound -Priority 500 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange *

  $WAFRule6 = New-AzureRmNetworkSecurityRuleConfig -Name HTTPS-Out -Description "Allow Outbound HTTPS" `
 -Access Allow -Protocol Tcp -Direction Outbound -Priority 110 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 443

  $WAFRule7 = New-AzureRmNetworkSecurityRuleConfig -Name HTTP-Out -Description "Allow Outbound HTTP" `
 -Access Allow -Protocol Tcp -Direction Outbound -Priority 120 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 80
 
   $WAFRule8 = New-AzureRmNetworkSecurityRuleConfig -Name DNS-Out -Description "Allow Outbound DNS" `
 -Access Allow -Protocol Tcp -Direction Outbound -Priority 130 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 53

 #endregion

##ASE Rules
#region
 $ASERule1 = New-AzureRmNetworkSecurityRuleConfig -Name AllAllowInboundASEManagement -Description "Allows All Inbound ASE Management" `
 -Access Allow -Protocol * -Direction Inbound -Priority 100 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix Virtualnetwork -DestinationPortRange 454-455

  $ASERule2 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowInboundHTTPS -Description "Allow Inbound HTTPS" `
 -Access Allow -Protocol Tcp -Direction Inbound -Priority 110 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix $hostingInfoWeb.internalIpAddress -DestinationPortRange 443

  $ASERule3 = New-AzureRmNetworkSecurityRuleConfig -Name AllAllowInboundHTTP -Description "Allow Inbound HTTP" `
 -Access Allow -Protocol Tcp -Direction Inbound -Priority 120 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix $hostingInfoWeb.internalIpAddress -DestinationPortRange 80

   $ASERule4 = New-AzureRmNetworkSecurityRuleConfig -Name AllAllowInboundVS1 -Description "Allow Inbound Visual Studio 2012 Debugging" `
 -Access Allow -Protocol * -Direction Inbound -Priority 130 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix $hostingInfoWeb.internalIpAddress -DestinationPortRange 4016

   $ASERule5 = New-AzureRmNetworkSecurityRuleConfig -Name AllAllowInboundVS2 -Description "Allow Inbound Visual Studio 2013 Debugging" `
 -Access Allow -Protocol * -Direction Inbound -Priority 140 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix $hostingInfoWeb.internalIpAddress -DestinationPortRange 4018

   $ASERule6 = New-AzureRmNetworkSecurityRuleConfig -Name AllAllowInboundVS3 -Description "Allow Inbound Visual Studio 2015 Debugging" `
 -Access Allow -Protocol * -Direction Inbound -Priority 150 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix $hostingInfoWeb.internalIpAddress -DestinationPortRange 4020

  $ASERule7 = New-AzureRmNetworkSecurityRuleConfig -Name AllAllowOutboundASEManagement -Description "Allow Outbound ASE Management" `
 -Access Allow -Protocol * -Direction Outbound -Priority 100 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 445
 
  $ASERule8 = New-AzureRmNetworkSecurityRuleConfig -Name AllAllowOutboundDNS -Description "Allow Outbound DNS" `
 -Access Allow -Protocol Tcp -Direction Outbound -Priority 120 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 53

   $ASERule9 = New-AzureRmNetworkSecurityRuleConfig -Name AllAllowOutboundHTTP -Description "Allow Outbound HTTP" `
 -Access Allow -Protocol Tcp -Direction Outbound -Priority 130 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 80

   $ASERule10 = New-AzureRmNetworkSecurityRuleConfig -Name AllAllowOutboundHTTPS -Description "Allow Outbound HTTPS" `
 -Access Allow -Protocol Tcp -Direction Outbound -Priority 140 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 443

  $ASERule11 = New-AzureRmNetworkSecurityRuleConfig -Name AllAllowSQL1 -Description "Allow SQL Connectivity" `
 -Access Allow -Protocol * -Direction Outbound -Priority 150 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 1433

  $ASERule12 = New-AzureRmNetworkSecurityRuleConfig -Name AllAllowSQL2 -Description "Allow ports for ADO.NET 4.5 client interactions" `
 -Access Allow -Protocol * -Direction Outbound -Priority 160 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 11000-11999

  $ASERule13 = New-AzureRmNetworkSecurityRuleConfig -Name AllAllowSQL3 -Description "Allow ports for ADO.NET 4.5 client interactions" `
 -Access Allow -Protocol * -Direction Outbound -Priority 170 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 14000-14999

  $ASERule14 = New-AzureRmNetworkSecurityRuleConfig -Name DenyAllOutbound `
 -Access Deny -Protocol * -Direction Outbound -Priority 500 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange *

  $ASERule15 = New-AzureRmNetworkSecurityRuleConfig -Name DenyAllInbound `
 -Access Deny -Protocol * -Direction Inbound -Priority 500 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange *
 #endregion

##Redis Rules
#region
$RedisRule1 = New-AzureRmNetworkSecurityRuleConfig -Name AllowOutboundHTTP -Description "Redis dependencies on Azure Storage/PKI (Internet)" `
 -Access Allow -Protocol Tcp -Direction Outbound -Priority 110 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 80

  $RedisRule2 = New-AzureRmNetworkSecurityRuleConfig -Name AllowOutboundHTTPS `
 -Access Allow -Protocol Tcp -Direction Outbound -Priority 120 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 443

  $RedisRule3 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowOutboundRedis1 `
 -Access Allow -Protocol Tcp -Direction Outbound -Priority 130 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix VirtualNetwork -DestinationPortRange 8443

   $RedisRule4 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowOutboundRedis2 `
 -Access Allow -Protocol Tcp -Direction Outbound -Priority 140 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix VirtualNetwork -DestinationPortRange 10221-10231

   $RedisRule5 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowOutboundRedis3 `
 -Access Allow -Protocol Tcp -Direction Outbound -Priority 150 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix AzureLoadBalancer -DestinationPortRange 10221-10231

   $RedisRule6 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowOutboundRedis4 `
 -Access Allow -Protocol Tcp -Direction Outbound -Priority 160 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix VirtualNetwork -DestinationPortRange 20226

   $RedisRule7 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowInboundRedis1 `
 -Access Allow -Protocol Tcp -Direction Inbound -Priority 170 `
 -SourceAddressPrefix VirtualNetwork -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 6379

   $RedisRule8 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowInboundRedis2 `
 -Access Allow -Protocol Tcp -Direction Inbound -Priority 180 `
 -SourceAddressPrefix AzureLoadBalancer -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 6379

   $RedisRule9 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowInboundRedis3 `
 -Access Allow -Protocol Tcp -Direction Inbound -Priority 190 `
 -SourceAddressPrefix AzureLoadBalancer -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 6380

   $RedisRule10 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowInboundRedis4 `
 -Access Allow -Protocol Tcp -Direction Inbound -Priority 200 `
 -SourceAddressPrefix VirtualNetwork -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 6380

   $RedisRule11 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowInboundRedis5 `
 -Access Allow -Protocol Tcp -Direction Inbound -Priority 210 `
 -SourceAddressPrefix VirtualNetwork -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 8443

   $RedisRule12 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowInboundRedis6 `
 -Access Allow -Protocol Tcp -Direction Inbound -Priority 220 `
 -SourceAddressPrefix VirtualNetwork -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 10221-10231

   $RedisRule13 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowInboundRedis7 `
 -Access Allow -Protocol Tcp -Direction Inbound -Priority 230 `
 -SourceAddressPrefix AzureLoadBalancer -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 10221-10231

   $RedisRule14 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowInboundRedis8 `
 -Access Allow -Protocol Tcp -Direction Inbound -Priority 240 `
 -SourceAddressPrefix VirtualNetwork -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 13000-13999

   $RedisRule15 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowInboundRedis9 `
 -Access Allow -Protocol Tcp -Direction Inbound -Priority 250 `
 -SourceAddressPrefix AzureLoadBalancer -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 13000-13999

   $RedisRule16 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowInboundRedis10 `
 -Access Allow -Protocol Tcp -Direction Inbound -Priority 260 `
 -SourceAddressPrefix VirtualNetwork -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 15000-15999

   $RedisRule17 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowInboundRedis11 `
 -Access Allow -Protocol Tcp -Direction Inbound -Priority 270 `
 -SourceAddressPrefix AzureLoadBalancer -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 15000-15999

   $RedisRule18 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowInboundRedis12 `
 -Access Allow -Protocol Tcp -Direction Inbound -Priority 280 `
 -SourceAddressPrefix VirtualNetwork -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 20226

   $RedisRule19 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowInboundRedis13 `
 -Access Allow -Protocol * -Direction Inbound -Priority 290 `
 -SourceAddressPrefix AzureLoadbalancer -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 8500

   $RedisRule20 = New-AzureRmNetworkSecurityRuleConfig -Name VnetAllowInboundRedis14 `
 -Access Allow -Protocol * -Direction Inbound -Priority 300 `
 -SourceAddressPrefix AzureLoadBalancer -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange 16001
 
   $RedisRule21 = New-AzureRmNetworkSecurityRuleConfig -Name DenyAllOutbound `
 -Access Deny -Protocol * -Direction Outbound -Priority 500 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange *

   $RedisRule22 = New-AzureRmNetworkSecurityRuleConfig -Name DenyAllInbound `
 -Access Deny -Protocol * -Direction Inbound -Priority 500 `
 -SourceAddressPrefix * -SourcePortRange * `
 -DestinationAddressPrefix * -DestinationPortRange *

 Write-Host "=>" -ForegroundColor Yellow
Write-Host "=> Building Network Security Groups" -ForegroundColor Yellow
##Build NSGs
#region
$WafNsg = New-AzureRmNetworkSecurityGroup -Name "WafNsg" -ResourceGroupName $RgName -Location $Region `
                                          -SecurityRules $WAFRule1,$WAFRule2,$WAFRule3,$WAFRule4,$WAFRule5,$WAFRule6,$WAFRule7,$WAFRule8,$WAFRule9,$WAFRule10,$WAFRule11,$WAFRule12,$WAFRule13,$WAFRule14,$WAFRule15,$WAFRule16 `
                                          -Force -WarningAction SilentlyContinue |out-null 
$AseWebNsg = New-AzureRmNetworkSecurityGroup -Name "AseWebNsg" -ResourceGroupName $RgName -Location $Region `
                                             -SecurityRules $ASERule1,$ASERule2,$ASERule3,$ASERule4,$ASERule5,$ASERule6,$ASERule7,$ASERule8,$ASERule9,$ASERule10,$ASERule11,$ASERule12,$ASERule13 `
                                             -Force -WarningAction SilentlyContinue | Out-Null
$RedisNsg = New-AzureRmNetworkSecurityGroup -Name "RedisNsg" -ResourceGroupName $RgName -Location $Region `
                                            -SecurityRules $RedisRule1,$RedisRule2,$RedisRule3,$RedisRule4,$RedisRule5,$RedisRule6,$RedisRule7,$RedisRule8,$RedisRule9,$RedisRule10,$RedisRule11,$RedisRule12,$RedisRule13,$RedisRule14,$RedisRule15,$RedisRule16,$RedisRule17,$RedisRule18,$RedisRule19,$RedisRule20,$RedisRule21 `
                                            -Force -WarningAction SilentlyContinue | Out-Null

Write-Host "=> Applying Network Security Groups to vNet" -ForegroundColor Yellow
##Apply NSGs to vNet
#region
$vnet = Get-AzureRmVirtualNetwork -ResourceGroupName $RgName -Name $VnetName
Set-AzureRmVirtualNetworkSubnetConfig -VirtualNetwork $vnet -Name $vnet.Subnets.name[0] `
                                      -AddressPrefix $vnet.Subnets.AddressPrefix[0]`
                                      -NetworkSecurityGroup $WafNSG  | Out-Null
Set-AzureRmVirtualNetwork -VirtualNetwork $vnet  | Out-Null
 
$vnet = Get-AzureRmVirtualNetwork -ResourceGroupName $RgName -Name $VnetName
Set-AzureRmVirtualNetworkSubnetConfig -VirtualNetwork $vnet -Name $vnet.Subnets.name[1] `
                                      -AddressPrefix $vnet.Subnets.AddressPrefix[1]`
                                      -NetworkSecurityGroup $AseWebNSG  | Out-Null
Set-AzureRmVirtualNetwork -VirtualNetwork $vnet  | Out-Null

$vnet = Get-AzureRmVirtualNetwork -ResourceGroupName $RgName -Name $VnetName
Set-AzureRmVirtualNetworkSubnetConfig -VirtualNetwork $vnet -Name $vnet.Subnets.name[2] `
                                      -AddressPrefix $vnet.Subnets.AddressPrefix[2]`
                                      -NetworkSecurityGroup $RedisNsg  | Out-Null
Set-AzureRmVirtualNetwork -VirtualNetwork $vnet  | Out-Null
#endregion

Write-Host "=>" -ForegroundColor Yellow
Write-Host "=> Adding Backend IPs to the Web Application Firewall" -ForegroundColor Yellow
#Add ILB Internal IP to the Backend Address Pool of the WAF
$AppGW = Get-AzureRmApplicationGateway -Name $AppGWName -ResourceGroupName $RgName
Set-AzureRmApplicationGatewayBackendAddressPool -Name appGatewayBackendPool `
                                                -BackendIPAddresses $hostingInfoApi.internalIpAddress, $hostingInfoWeb.internalIpAddress `
                                                -ApplicationGateway $AppGW  | Out-Null
Set-AzureRmApplicationGateway -ApplicationGateway $AppGW  | Out-Null

Write-Host "=>" -ForegroundColor Yellow
Write-Host "=>" -ForegroundColor Yellow
Write-Host "=> Deployment Complete!" -ForegroundColor Yellow