# Azure Mission Partner Environment - Scenario for Terraform & Azure NoOps Accelerator

## Overview

This Mission Partner Environment (MPE) is a scenario that demonstrates how to deploy a set of Azure resources using Terraform. The MPE is intended to be used as a reference for how to deploy Azure resources using Terraform.

## Accounting for Separation of Duties

The steps in the MPE are intended to imitate how an organization could separate the deployment of different Azure components across teams into separate code repos, or have them executed by different pipelines with specific credentials, even though the code in this repo is contained in a single folder in a single repository.

## Terraform State Management

In this MPE, state is stored in an Azure Storage account that was created out-of-band from the rest of the deployment. All deployments reference this storage account to either store state or reference variables from other parts of the deployment however you may choose to use other tools for state management, like Terraform Cloud after making the necessary code changes.

## Terraform Variable Definitons File

In this MPE, there is a common variable defintions file [parameters.<environment>.tfvars](./tfvars) that is shared across all deployments. Review each section and update the variable definitons file as needed.

## Prerequisites for Deployment

1. Install or upgrade [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli), install [Terraform](https://www.terraform.io/downloads.html)
    
    ### To authenticate Azure CLI
    `az login`

    ### To set a specific subscription
    `az account list --output table`<br>
    `az account set --subscription <name-of-subscription>`

2. If not already registered in the subscription, use the following Azure CLI commands to register the required resource providers for Azure Spring Apps:

    `az provider register --namespace 'Microsoft.AppPlatform'`

    `az provider register --namespace 'Microsoft.ContainerService'`

    `az provider register --namespace 'Microsoft.ServiceLinker'`

3. Obtain the ObjectID of the service principal for Azure Spring Apps. This ID is unique per Azure AD Tenant. In Step 4, set the value of variable SRINGAPPS_SPN_OBJECT_ID to the result from this command.

    `az ad sp show --id 0000000-0000-0000-0000-00000000000 --query id --output tsv`

4. Modify the variables within the Global section of the variable definitons file paramaters.test.tfvars as needed

 ```bash
    # EXAMPLE
    
    ##################################################
    ## Global
    ##################################################
    #
    required = {
    org_name           = "ampe"
    deploy_environment = "prod" # dev | test | prod
    environment        = "public" # public | usgovernement
    metadata_host      = "management.azure.com" # management.azure.com | management.usgovcloudapi.net | management.chinacloudapi.cn | management.microsoftazure.de
    }

    default_location      = "eastus"

    # Resource Locks
    enable_resource_locks = false

    contact_emails = ["mpe@afmpe.com"] # email addresses to send alerts to for this subscription

    ################################
    # Landing Zone Configuration  ##
    ################################

    ##################
    # Ops Logging  ###
    ##################

    # ops_logging_name = "ops-logging-core"
    # enable_sentinel = true
    # log_analytics_workspace_sku = "PerGB2018"
    # log_analytics_logs_retention_in_days = 30

    ##########
    # Hub  ###
    ##########

    # hub_name = "hub-core"
    # hub_vnet_address_space = ["10.0.100.0/24"]
    # hub_vnet_subnet_address_prefixes = ["10.0.100.128/27"]
    # hub_vnet_subnet_service_endpoints = [
    #     "Microsoft.KeyVault",
    #     "Microsoft.Sql",
    #     "Microsoft.Storage",
    # ]

    # enable_firewall = true
    # enable_force_tunneling = true
    # firewall_supernet_IP_address = "10.0.96.0/19"
    # enable_bastion_host = true

    #################
    # Operations  ###
    #################

    #################
    # Operations  ###
    #################

    # ops_name = "ops-core"
    # ops_vnet_address_space = ["10.0.115.0/24"]
    # ops_vnet_subnet_address_prefixes = ["10.0.115.0/27"]
    # ops_vnet_subnet_service_endpoints = [
    #     "Microsoft.KeyVault",
    #     "Microsoft.Sql",
    #     "Microsoft.Storage",
    # ]

    ######################
    # Shared Services  ###
    ######################

    # svcs_name = "svcs-core"
    # svcs_vnet_address_space = ["10.0.120.0/24"]
    # svcs_vnet_subnet_address_prefixes = ["10.0.120.128/27"]
    # svcs_vnet_subnet_service_endpoints = [
    #     "Microsoft.KeyVault",
    #     "Microsoft.Sql",
    #     "Microsoft.Storage",
    # ]


    # default_tags = { 
    #    project = "AMPE"
    # }
```

## Deployment

1. [Creation of Azure Storage Account for State Management](./docs/State-Storage.md)

2. [Creation of the MPE Management Groups Structure & subscription placement](./docs/Management-Groups.md)

3. [Creation of MPE Landing Zone Network & its respective Components](./docs/LZ-Network.md)

4. [Creation of Shared components for this deployment](./docs/LZ-SharedResources.md)

5. [Optional: Creation of Application Gateway](./docs/LZ-AppGateway.md)

6. [Cleanup](./docs/cleanup.md)

7. [E2E Deployment using GitHub Action](./docs/e2e-githubaction.md)

## Known Issues / Notes

- Please take the following actions before attempting to destroy this deployment.
