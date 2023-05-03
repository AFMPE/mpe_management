# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy a workload spoke virtual network in Azure Partner Landing Zone
DESCRIPTION: The following components will be options in this deployment
             * Virtual Network
             * Subnets
             * Network Security Groups
             * Network Security Group Rules
             * Service Endpoints
             * Private Endpoints
             * Private Link Services
             * Resource Locks
AUTHOR/S: jspinella
*/

######################################
### Workload Spoke Configuration   ###
######################################

// Resources for the Operations Spoke
module "mod_workload_network" {
  source  = "azurenoops/overlays-hubspoke/azurerm//modules/virtual-network-spoke"
  version = ">= 1.0.0"

  #####################################
  ## Global Settings Configuration  ###
  #####################################

  location           = module.mod_azure_region_lookup.location_cli
  deploy_environment = local.deploy_environment
  org_name           = local.org_name
  environment        = local.environment
  workload_name      = local.wl_name
  
  ##################################################
  ## Operations Spoke Configuration   (Default)  ###
  ##################################################

  # Indicates if the spoke is deployed to the same subscription as the hub. Default is true.
  is_spoke_deployed_to_same_hub_subscription = local.deployed_to_hub_subscription

  # Provide valid VNet Address space for spoke virtual network.  
  virtual_network_address_space = local.wl_vnet_address_space

  # Provide valid subnet address prefix for spoke virtual network. Subnet naming is based on default naming standard
  spoke_subnet_address_prefix                         = local.wl_subnet_addresses
  spoke_subnet_service_endpoints                      = local.wl_subnet_service_endpoints
  spoke_private_endpoint_network_policies_enabled     = false
  spoke_private_link_service_network_policies_enabled = true

  # Hub Virtual Network ID
  hub_virtual_network_id = var.hub_virtual_network_id

  # Firewall Private IP Address 
  hub_firewall_private_ip_address = var.firewall_private_ip

  # (Optional) Operations Network Security Group
  # This is default values, do not need this if keeping default values
  # NSG rules are not created by default for Azure NoOps Hub Subnet

  # To deactivate default deny all rule
  deny_all_inbound = local.deny_all_inbound

  # Network Security Group Rules to apply to the Operatioms Virtual Network
  nsg_additional_rules = local.wl_nsg_rules

  #############################
  ## Misc Configuration     ###
  #############################

  # By default, this will apply resource locks to all resources created by this module.
  # To disable resource locks, set the argument to `enable_resource_locks = false`.
  enable_resource_locks = local.enable_resource_locks

  # Tags
  add_tags = local.default_tags # Tags to be applied to all resources
}
