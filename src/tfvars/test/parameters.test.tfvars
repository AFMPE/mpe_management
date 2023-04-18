# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This is a sample configuration file for the MPE Landing Zone
# This file is used to configure the MPE Landing Zone.  
# It is used to set the default values for the variables used in the MPE Landing Zone.  The values in this file can be overridden by setting the same variable in the terraform.tfvars file.

#####################################
# Management Groups Configuration  ##
#####################################

root_management_group_id           = "ampe" # the root management group id for this subscription
root_management_group_display_name = "ampe" # the root management group display name for this subscription

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

# Used during testing, comment when not testing
subscription_id_hub = "930a247f-b4fa-4f1b-ad73-6a03cf1d0f4e"

####################################
## Security Center Configuration  ##
####################################

contact_emails = ["mpe@afmpe.com"] # email addresses to send alerts to for this subscription

#########################################
## Remote Storage State Configuration  ##
#########################################

# Deployment state storage information
state_sa_name           = "afmpetfmgtprodh8dc4qua"
state_sa_rg             = "afmpe-network-artifacts-rg"
state_sa_container_name = "core-mgt-test-tfstate"

################################
# Landing Zone Configuration  ##
################################

#########################
# Hub Virtual Network ###
#########################

hub_name                         = "hub-core"
hub_vnet_address_space           = ["10.0.100.0/24"]
hub_vnet_subnet_address_prefixes = ["10.0.100.128/27"]
hub_vnet_subnet_service_endpoints = [
  "Microsoft.KeyVault",
  "Microsoft.Sql",
  "Microsoft.Storage",
]

enable_firewall              = true
enable_force_tunneling       = true
firewall_supernet_IP_address = "10.0.96.0/19"
enable_bastion_host          = true

######################################
# Operations Spoke Virtual Network ###
######################################

ops_name                         = "ops-core"
ops_vnet_address_space           = ["10.0.115.0/24"]
ops_vnet_subnet_address_prefixes = ["10.0.115.0/27"]
ops_vnet_subnet_service_endpoints = [
  "Microsoft.KeyVault",
  "Microsoft.Sql",
  "Microsoft.Storage",
]

#########################
# OperationL Logging  ###
#########################

ops_logging_name                     = "ops-logging-core"
enable_sentinel                      = true
log_analytics_workspace_sku          = "PerGB2018"
log_analytics_logs_retention_in_days = 30

###########################################
# Shared Services Spoke Virtual Network ###
###########################################

svcs_name                         = "svcs-core"
svcs_vnet_address_space           = ["10.0.120.0/24"]
svcs_vnet_subnet_address_prefixes = ["10.0.120.0/27"]
svcs_pe_subnet_address_prefixes   = ["10.0.120.32/27"]
svcs_vnet_subnet_service_endpoints = [
  "Microsoft.KeyVault",
  "Microsoft.Sql",
  "Microsoft.Storage",
]
