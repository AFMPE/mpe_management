# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

root_management_group_id ="ampe" # the root management group id for this subscription
root_management_group_display_name ="ampe" # the root management group display name for this subscription

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

ops_logging_name = "ops-logging-core"
enable_sentinel = true
log_analytics_workspace_sku = "PerGB2018"
log_analytics_logs_retention_in_days = 30

##########
# Hub  ###
##########

hub_name = "hub-core"
hub_vnet_address_space = ["10.0.100.0/24"]
hub_vnet_subnet_address_prefixes = ["10.0.100.128/27"]
hub_vnet_subnet_service_endpoints = [
    "Microsoft.KeyVault",
    "Microsoft.Sql",
    "Microsoft.Storage",
  ]

enable_firewall = true
enable_force_tunneling = true
firewall_supernet_IP_address = "10.0.96.0/19"
enable_bastion_host = true

#################
# Operations  ###
#################

ops_name = "ops-core"
ops_vnet_address_space = ["10.0.115.0/24"]
ops_vnet_subnet_address_prefixes = ["10.0.115.0/27"]
ops_vnet_subnet_service_endpoints = [
    "Microsoft.KeyVault",
    "Microsoft.Sql",
    "Microsoft.Storage",
  ]

######################
# Shared Services  ###
######################

svcs_name = "svcs-core"
svcs_vnet_address_space = ["10.0.120.0/24"]
svcs_vnet_subnet_address_prefixes = ["10.0.120.128/27"]
svcs_vnet_subnet_service_endpoints = [
    "Microsoft.KeyVault",
    "Microsoft.Sql",
    "Microsoft.Storage",
  ]