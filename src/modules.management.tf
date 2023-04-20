# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy an Azure Partner Environment
DESCRIPTION: The following components will be options in this deployment
             * Management Group Hierarchy
             * Custom Role Definitions
             * Hub/Spoke Network Architecture
AUTHOR/S: jspinella
*/

########################################
###  Management Group Configuations  ###
########################################

module "management_groups" {
  source = "./modules/management_groups"

  # Global Configuration
  root_management_group_id           = var.root_management_group_id
  root_management_group_display_name = var.root_management_group_display_name
  subscription_id_hub                = var.subscription_id_hub
  subscription_id_identity           = coalesce(var.subscription_id_identity, var.subscription_id_hub)
  subscription_id_operations         = coalesce(var.subscription_id_operations, var.subscription_id_hub)
  subscription_id_sharedservices     = coalesce(var.subscription_id_sharedservices, var.subscription_id_hub)
  subscription_id_internal           = var.subscription_id_internal
  subscription_id_sandbox            = var.subscription_id_sandbox
  subscription_id_partners_gsa_dev   = var.subscription_id_partners_gsa_dev
  subscription_id_partners_gsa_prod  = var.subscription_id_partners_gsa_prod
}

#############################################
### Custom Role Definitions Configuations ###
#############################################

################################
### Hub/Spoke Configuations  ###
################################

module "landing_zone" {
  source = "./modules/landing_zone"

  # Global Configuration
  required                       = var.required
  location                       = var.default_location
  subscription_id_hub            = var.subscription_id_hub
  subscription_id_operations     = coalesce(var.subscription_id_operations, var.subscription_id_hub)
  subscription_id_identity       = coalesce(var.subscription_id_identity, var.subscription_id_hub)
  subscription_id_sharedservices = coalesce(var.subscription_id_sharedservices, var.subscription_id_hub)

  # Resource Lock Configuration
  enable_resource_locks = var.enable_resource_locks
  lock_level            = var.lock_level

  # Operations Logging Configuration
  ops_logging_name                     = var.ops_logging_name
  enable_sentinel                      = var.enable_sentinel
  log_analytics_workspace_sku          = var.log_analytics_workspace_sku
  log_analytics_logs_retention_in_days = var.log_analytics_logs_retention_in_days

  # Hub Configuration
  hub_name                          = var.hub_name
  hub_vnet_address_space            = var.hub_vnet_address_space
  hub_vnet_subnet_address_prefixes  = var.hub_vnet_subnet_address_prefixes
  hub_vnet_subnet_service_endpoints = var.hub_vnet_subnet_service_endpoints
  enable_firewall                   = var.enable_firewall
  enable_force_tunneling            = var.enable_force_tunneling
  enable_bastion_host               = var.enable_bastion_host
  firewall_supernet_IP_address      = var.firewall_supernet_IP_address

  # Operations Spoke Configuration
  ops_name                          = var.ops_name
  ops_vnet_address_space            = var.ops_vnet_address_space
  ops_vnet_subnet_address_prefixes  = var.ops_vnet_subnet_address_prefixes
  ops_vnet_subnet_service_endpoints = var.ops_vnet_subnet_service_endpoints

  # Shared Services Spoke Configuration
  svcs_name                          = var.svcs_name
  svcs_vnet_address_space            = var.svcs_vnet_address_space
  svcs_vnet_subnet_address_prefixes  = var.svcs_vnet_subnet_address_prefixes
  svcs_vnet_subnet_service_endpoints = var.svcs_vnet_subnet_service_endpoints

}
