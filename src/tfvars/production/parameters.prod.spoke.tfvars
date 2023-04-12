# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License. 

###########################
## Global Configuration  ##
###########################

required = {
  org_name           = "ampe"                 # This Prefix will be used on most deployed resources.  10 Characters max.
  deploy_environment = "prod"                 # dev | test | prod
  environment        = "public"               # public | usgovernment
  metadata_host      = "management.azure.com" # management.azure.com | management.usgovcloudapi.net
}

# The default region to deploy to
default_location = "eastus"

# Enable locks on resources
enable_resource_locks = false

#########################################
## Remote Storage State Configuration  ##
#########################################

# Deployment state storage information
state_sa_name           = "afmpetfmgtprodh8dc4qua"
state_sa_rg             = "afmpe-network-artifacts-rg"
state_sa_container_name = "core-mgt-prod-tfstate"

###############################
# Workload Virtual Network  ###
###############################

wl_vnet_address_space           = ["10.0.125.0/24"]
wl_vnet_subnet_address_prefixes = ["10.0.125.0/27"]
wl_vnet_subnet_service_endpoints = [
  "Microsoft.KeyVault",
  "Microsoft.Sql",
  "Microsoft.Storage",
]
