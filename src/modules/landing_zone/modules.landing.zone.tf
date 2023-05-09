# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy an SCCA Compliant Platform Hub/Spoke Landing Zone
DESCRIPTION: The following components will be options in this deployment
              * Hub Virtual Network (VNet)              
              * Bastion Host (Optional)
              * DDos Standard Plan (Optional)
              * Microsoft Defender for Cloud (Optional)              
            * Spokes              
              * Operations (Tier 1)
              * Shared Services (Tier 2)
            * Logging
              * Azure Sentinel
              * Azure Log Analytics
            * Azure Firewall
            * Private DNS Zones - Details of all the Azure Private DNS zones can be found here --> [https://docs.microsoft.com/en-us/azure/private-link/private-endpoint-dns#azure-services-dns-zone-configuration](https://docs.microsoft.com/en-us/azure/private-link/private-endpoint-dns#azure-services-dns-zone-configuration)
AUTHOR/S: jspinella
*/

################################
### Hub/Spoke Configuations  ###
################################

###########################################
### Operational Logging Configuration   ###
###########################################

module "mod_operational_logging" {
  providers = { azurerm = azurerm.operations }
  source    = "azurenoops/overlays-hubspoke/azurerm//modules/operational-logging"
  version   = ">= 1.0.0"

  #####################################
  ## Global Settings Configuration  ###
  #####################################

  location           = module.mod_azure_region_lookup.location_cli
  deploy_environment = local.deploy_environment
  org_name           = local.org_name
  environment        = local.environment
  workload_name      = local.ops_logging_name

  #############################
  ## Logging Configuration  ###
  #############################

  # (Optional) Enable Azure Sentinel
  enable_sentinel = local.enable_sentinel

  # (Required) To enable Azure Monitoring
  # Sku Name - Possible values are PerGB2018 and Free
  # Log Retention in days - Possible values range between 30 and 730
  log_analytics_workspace_sku          = local.log_analytics_workspace_sku
  log_analytics_logs_retention_in_days = local.log_analytics_retention

  ######################################
  ## Private EndPoint Configuration  ###
  ######################################

  # (Required) To enable Private Endpoint
  private_endpoint_subnet_id = module.mod_ops_network.default_subnet_id

  ################################
  ## Defender Configuration    ###
  ################################

  # Enable Security Center API Setting
  enable_security_center_setting = false

  # Enable auto provision of log analytics agents on VM's if they doesn't exist. 
  enable_security_center_auto_provisioning = "Off"

  # Subscription Security Center contacts
  # One or more email addresses seperated by commas not supported by Azure proivider currently
  security_center_contacts = local.security_center_contacts

  #############################
  ## Misc Configuration     ###
  #############################

  # By default, this will apply resource locks to all resources created by this module.
  # To disable resource locks, set the argument to `enable_resource_locks = false`.
  enable_resource_locks = local.enable_resource_locks

  # Tags
  add_tags = local.operations_resources_tags # Tags to be applied to all resources
}

#######################################
### Hub Network Configuration       ###
#######################################

module "mod_hub_network" {
  providers = { azurerm = azurerm.hub }
  source    = "azurenoops/overlays-hubspoke/azurerm//modules/virtual-network-hub"
  version   = ">= 1.0.0"

  #####################################
  ## Global Settings Configuration  ###
  #####################################

  location           = module.mod_azure_region_lookup.location_cli
  deploy_environment = local.deploy_environment
  org_name           = local.org_name
  environment        = local.environment
  workload_name      = local.hub_name

  #########################
  ## Hub Configuration  ###
  #########################

  # (Required)  Hub Virtual Network Parameters   
  virtual_network_address_space = local.hub_vnet_address_space

  # (Optional) Create DDOS Plan. Default is false
  create_ddos_plan = local.create_ddos_plan

  # (Optional) Hub Network Watcher
  create_network_watcher = local.create_network_watcher

  # (Required) Hub Subnets 
  # Default Subnets, Service Endpoints
  # This is the default subnet with required configuration, check README.md for more details
  # First address ranges from VNet Address space reserved for Firewall Subnets. 
  # ex.: For 10.0.100.128/27 address space, usable address range start from 10.0.100.0/24 for all subnets.
  # default subnet name will be set as per Azure NoOps naming convention by defaut.
  hub_subnet_address_prefix    = local.hub_subnet_addresses
  hub_subnet_service_endpoints = local.hub_subnet_service_endpoints

  hub_private_endpoint_network_policies_enabled     = false
  hub_private_link_service_network_policies_enabled = true

  add_subnets = local.hub_vnet_subnets

  # (Optional) Hub Network Security Group
  # This is default values, do not need this if keeping default values
  # NSG rules are not created by default for Azure NoOps Hub Subnet

  # To deactivate default deny all rule
  deny_all_inbound = local.hub_deny_all_inbound

  ##############################
  ## Firewall Configuration  ###
  ##############################

  # Firewall Settings
  # By default, Azure NoOps will create Azure Firewall in Hub VNet. 
  # If you do not want to create Azure Firewall, 
  # set enable_firewall to false. This will allow different firewall products to be used (Example: F5).  
  enable_firewall = local.enable_firewall

  # By default, forced tunneling is enabled for Azure Firewall.
  # If you do not want to enable forced tunneling, 
  # set enable_forced_tunneling to false.
  enable_forced_tunneling = local.enable_forced_tunneling

  // Firewall Subnets
  fw_client_snet_address_prefix     = local.fw_client_snet_address_prefixes
  fw_management_snet_address_prefix = local.fw_management_snet_address_prefixes

  # Firewall Config
  # This is default values, do not need this if keeping default values
  firewall_config = local.firewall_config

  # # (Optional) specify the Network rules for Azure Firewall l
  # This is default values, do not need this if keeping default values
  network_rule_collection = local.network_rule_collection

  # (Optional) specify the application rules for Azure Firewall
  # This is default values, do not need this if keeping default values
  application_rule_collection = local.application_rule_collection

  #############################
  ## Bastion Configuration  ###
  #############################

  # By default, this module will create a bastion host, 
  # and set the argument to `enable_bastion_host = false`, to disable the bastion host.
  enable_bastion_host                 = local.enable_bastion_host
  azure_bastion_host_sku              = local.bastion_host_sku
  azure_bastion_subnet_address_prefix = local.bastion_subnet_address_prefixes

  # Bastion Public IP
  azure_bastion_public_ip_allocation_method = "Static"
  azure_bastion_public_ip_sku               = "Standard"

  #############################
  ## Misc Configuration     ###
  #############################

  # By default, this will apply resource locks to all resources created by this module.
  # To disable resource locks, set the argument to `enable_resource_locks = false`.
  enable_resource_locks = local.enable_resource_locks

  # Tags
  add_tags = local.hub_resources_tags # Tags to be applied to all resources
}

#############################
### Spoke Configuration   ###
#############################

// Resources for the Operations Spoke
module "mod_ops_network" {
  providers = { azurerm = azurerm.operations }
  source    = "azurenoops/overlays-hubspoke/azurerm//modules/virtual-network-spoke"
  version   = ">= 1.0.0"

  #####################################
  ## Global Settings Configuration  ###
  #####################################

  location           = module.mod_azure_region_lookup.location_cli
  deploy_environment = local.deploy_environment
  org_name           = local.org_name
  environment        = local.environment
  workload_name      = local.ops_name

  ##################################################
  ## Operations Spoke Configuration   (Default)  ###
  ##################################################

  # Indicates if the spoke is deployed to the same subscription as the hub. Default is true.
  is_spoke_deployed_to_same_hub_subscription = local.deployed_to_hub_subscription

  # Provide valid VNet Address space for spoke virtual network.  
  virtual_network_address_space = local.ops_vnet_address_space

  # Provide valid subnet address prefix for spoke virtual network. Subnet naming is based on default naming standard
  spoke_subnet_address_prefix                         = local.ops_subnet_addresses
  spoke_subnet_service_endpoints                      = local.ops_subnet_service_endpoints
  spoke_private_endpoint_network_policies_enabled     = false
  spoke_private_link_service_network_policies_enabled = true

  # Hub Virtual Network ID
  hub_virtual_network_id = module.mod_hub_network.hub_virtual_network_id

  # Firewall Private IP Address 
  hub_firewall_private_ip_address = module.mod_hub_network.firewall_private_ip

  # (Optional) Enable forced tunneling for Route Table
  enable_forced_tunneling_on_route_table = local.enable_forced_tunneling

  # (Optional) Operations Network Security Group
  # This is default values, do not need this if keeping default values
  # NSG rules are not created by default for Azure NoOps Hub Subnet

  # To deactivate default deny all rule
  deny_all_inbound = local.deny_all_inbound

  # Network Security Group Rules to apply to the Operatioms Virtual Network
  nsg_additional_rules = local.ops_nsg_rules

  #############################
  ## Peering Configuration  ###
  #############################

  allow_virtual_spoke_network_access = local.allow_virtual_spoke_network_access
  allow_forwarded_spoke_traffic      = local.allow_forwarded_spoke_traffic
  allow_gateway_spoke_transit        = local.allow_gateway_spoke_transit
  use_remote_spoke_gateway           = local.use_remote_spoke_gateway

  #############################
  ## Misc Configuration     ###
  #############################

  # By default, this will apply resource locks to all resources created by this module.
  # To disable resource locks, set the argument to `enable_resource_locks = false`.
  enable_resource_locks = local.enable_resource_locks

  # Tags
  add_tags = local.operations_resources_tags # Tags to be applied to all resources
}

// Resources for the Shared Services Spoke
module "mod_svcs_network" {
  providers = { azurerm = azurerm.sharedservices }
  source    = "azurenoops/overlays-hubspoke/azurerm//modules/virtual-network-spoke"
  version   = ">= 1.0.0"

  #####################################
  ## Global Settings Configuration  ###
  #####################################

  location           = module.mod_azure_region_lookup.location_cli
  deploy_environment = local.deploy_environment
  org_name           = local.org_name
  environment        = local.environment
  workload_name      = local.svcs_name

  #######################################################
  ## Shared Services Spoke Configuration   (Default)  ###
  #######################################################

  # Indicates if the spoke is deployed to the same subscription as the hub. Default is true.
  is_spoke_deployed_to_same_hub_subscription = local.deployed_to_hub_subscription

  # Provide valid VNet Address space for spoke virtual network.  
  virtual_network_address_space = local.svcs_vnet_address_space

  # Provide valid subnet address prefix for spoke virtual network. Subnet naming is based on default naming standard
  spoke_subnet_address_prefix                         = local.svcs_subnet_addresses
  spoke_subnet_service_endpoints                      = local.svcs_subnet_service_endpoints
  spoke_private_endpoint_network_policies_enabled     = false
  spoke_private_link_service_network_policies_enabled = true

  # Add Private Endpoint Subnet
  add_subnets = local.svcs_vnet_subnets

  # Hub Virtual Network ID
  hub_virtual_network_id = module.mod_hub_network.hub_virtual_network_id

  # Firewall Private IP Address 
  hub_firewall_private_ip_address = module.mod_hub_network.firewall_private_ip

  # (Optional) Enable forced tunneling for Route Table
  enable_forced_tunneling_on_route_table = local.enable_forced_tunneling

  # (Optional) Shared Services Network Security Group
  # This is default values, do not need this if keeping default values
  # NSG rules are not created by default for Azure Nosvcs Hub Subnet

  # To deactivate default deny all rule
  deny_all_inbound = local.deny_all_inbound

  # Network Security Group Rules to apply to the Shared Services Virtual Network
  nsg_additional_rules = local.svcs_nsg_rules

  #############################
  ## Peering Configuration  ###
  #############################

  allow_virtual_spoke_network_access = var.allow_virtual_spoke_network_access
  allow_forwarded_spoke_traffic      = var.allow_forwarded_spoke_traffic
  allow_gateway_spoke_transit        = var.allow_gateway_spoke_transit
  use_remote_spoke_gateway           = var.use_remote_spoke_gateway

  #############################
  ## Misc Configuration     ###
  #############################

  # By default, this will apply resource locks to all resources created by this module.
  # To disable resource locks, set the argument to `enable_resource_locks = false`.
  enable_resource_locks = local.enable_resource_locks

  # Tags
  add_tags = local.sharedservices_resources_tags # Tags to be applied to all resources
}

