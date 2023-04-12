# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License. 

# This is a sample configuration file for the MPE Landing Zone Workload Spoke
# This file is used to configure the MPE Landing Zone Workload Spoke.  
# It is used to set the default values for the variables used in the MPE Landing Zone Workload Spoke.  The values in this file can be overridden by setting the same variable in the terraform.tfvars file.

###########################
## Global Configuration  ##
###########################

required = {
  org_name           = "ampe"                 # This Prefix will be used on most deployed resources.  10 Characters max.
  deploy_environment = "test"                 # dev | test | prod
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
state_sa_container_name = "core-mgt-test-tfstate"

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
