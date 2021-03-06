![alt text](images/azblueprints.png "Template Deployment Sequence")
# Blueprints-PaaS-ASE Deployment with Azure Automation

## Contents
- [1. Solution Overview](#1-solution-overview)
- [2. Solution Design](#2-solution-design)
	- [2.1 Architecture](#21-architecture)
- [3. Deployment](#3-deployment) 
	- [3.1 Installation Prerequisites](#31-installation-prerequisites)
	- [3.2 Deployment Steps Overview](#32-deployment-steps-overview)
        - [3.2.1 Configure required assets](#321-Configure-required-assets)
        - [3.2.2 Create the Azure Deploy runbook to execute the deployment ](#322-Create-the-Azure-Deploy-runbook-to-execute-the-deployment)
        - [3.2.3 Create webhook to programitcally initiate the runbook and pass parameters](#323-Create-webhook-to-programitcally-initiate-the-runbook-and-pass-parameters)
        - [3.2.3 Register Hybrid Runbook Worker](#324-Register-Hybrid-Runbook-Worker)
    - [3.3 Expected Output](#33-expected-output)


## 1. Solution Overview

![alt text](images/2017-06-09_11-49-06.png "Template Deployment Sequence via Azure Automation")

This Blueprint deploys a fully automated secure baseline Azure ARM Template as described here https://github.com/mayurshintre/Blueprints-PaaS-ASE/tree/master/ase-ilb-blueprint via Azure Automation

## 2. Solution Design

### 2.1 Architecture
The diagram below illustrates the deployment topology and architecture of the solution:

![alt text](images/2017-06-09_13-41-10.png "Solution Diagram")

## 3. Deployment Guide

### 3.1 Installation Prerequisites
This solution utilizes a combination of ARM templates and PowerShell. In order to deploy the solution. When deployed to Hybrid Runbook Worker the solution will automatically install the items below: 

+ [Azure Active Directory V2 PowerShell Module](https://technet.microsoft.com/en-us/library/dn975125.aspx#Anchor_5)
+ [Azure Resource Manager PowerShell Module via WebPi Installer](http://go.microsoft.com/fwlink/?LinkId=255386)

### 3.2 Deployment Steps Overview
In order to deploy via Azure Automation you will need to configure several assets utilizing Azure Automation asset store and import required modules

1. Configure required assets
2. Create the Azure Deploy runbook to execute the deployment 
3. Create webhook to programitcally initiate the runbook and pass parameters
4. Register Hybrid Runbook Worker

#### 3.2.1 Configure Asset Variables 
Configure variables needed for the deployment
+ ASEB-ClientID - Client id of Azure AD application needed to perform REST API calls
+ ASEB-ClientKey - Key to the application used to authenicate the REST API call (This can be stored as a secure string)
+ ASEB-Region - Azure region the ASE Blueprint will be deployed to
+ ASEB-ResourGroup - Name of target Resource Group
+ ASEB-SubscriptionID - ID of the target Azure Subscription
+ ASEB-TemplateURI - URI used to download the deployment JSON (Example https://raw.githubusercontent.com/mayurshintre/Blueprints-PaaS-ASE/master/ase-ilb-blueprint/azuredeploy.json)

#### 3.2.2 Create Runbook
+ Automation Account =>Runbooks => Add a Runbook => Import an existing runbook => Runbook file (point this to "AzureRM-ASEB-DeployAA.ps1" powershell script listed in the solution)
+ Runbook type should be "PowerShell"

#### 3.2.3 Crate Webhook
+ Automation Account =>Runbooks => Azure Deploy Runbook => Webhooks => Add Webhook (Note: be sure to copy access token needed to initiate the webhook)
+ Example Powershell Webhook, parameters in the webhook will be passed to Azure Deploy runbook
```PowerShell
$webhookurl = 'WEBHOOK ACCESS TOKEN'

$body = @{
    SystemPrefixName = "ASEB1"
    vnetAddressPrefix = "10.0.0.0"
    vnetAddressPrefixCIDR = 16
    WAFSubnetPrefix = "10.0.0.0"
    WAFSubnetPrefixCIDR = 27
    WebAppSubnetPrefix = "10.0.1.0"
    WebAppSubnetPrefixCIDR = 26
    RedisCacheSubnetPrefix = "10.0.3.0"
    RedisCacheSubnetPrefixCIDR = 27
    dnsOption = "customdns"
    redisShardCount = 2
    redisCacheCapacity = 1
    appServicePlanNameWeb = "ASPNameWeb"
    WebDNS = "Web.demo"
    internalLoadBalancingMode = 1
    frontEndSize = "Medium"
    frontEndCount = 2
    workerPoolOneInstanceSize = "Small"
    workerPoolOneInstanceCount = 2
    workerPoolTwoInstanceSize = "Small"
    workerPoolTwoInstanceCount = 2
    workerPoolThreeInstanceSize = "Small"
    workerPoolThreeInstanceCount = 0
    numberOfWorkersFromWorkerPool = 2
    workerPool  = "WP1"
    applicationGatewaySize = "WAF_Medium"
    wafEnabled = $true
    WafCapacity = 2
    databaseEdition = "Basic"
    databaseServiceObjectiveName = "Basic"
    sqlAdministratorLogin = "Master"
}


$params = @{
    ContentType = 'application/json'
    Body = ($body | convertto-json)
    Method = 'Post'
    URI = $webhookurl
}

Invoke-RestMethod @params -Verbose
```

#### 3.2.4 Register Hybrid Runbook Worker
Current version of the deployment has a dependancy on 2 DLL's that get deployed with WebPi installer and therefore needs to execure on a Hybrid Runbook Worker
+ Follow our documentation for registering Hybrid Runbook Workers here: [Automate resources in your data center with Hybrid Runbook Worker](https://docs.microsoft.com/en-us/azure/automation/automation-hybrid-runbook-worker)

### 3.3 Expected Output
After initiating the Azure Deploy runbook you can monitor the deployment process in the runbook output pane. You will see "Deployment Complete!" when the job is complete

![alt text](images/2017-06-09_14-46-43.png "Output")