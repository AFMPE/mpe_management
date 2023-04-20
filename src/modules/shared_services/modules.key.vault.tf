# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*  
SUMMARY:  Module to deploy a Key Vault
DESCRIPTION: This module deploys a Bastion Jumpbox to the Shared Services Network
AUTHOR/S: jspinella
*/

###############################
## Key Vault Configuration  ###
###############################
module "mod_shared_keyvault" {
  source  = "azurenoops/overlays-key-vault/azurerm"
  version = "~> 1.0.0"

  # By default, this module will create a resource group and 
  # provide a name for an existing resource group. If you wish 
  # to use an existing resource group, change the option 
  # to "create_key_vault_resource_group = false." 
  create_key_vault_resource_group = false
  custom_resource_group_name      = data.terraform_remote_state.landing_zone.outputs.svcs_resource_group_name
  deploy_environment              = local.deploy_environment
  org_name                        = local.org_name
  environment                     = local.environment
  workload_name                   = "shared-keys"

  # This is to enable the features of the key vault
  enabled_for_deployment          = var.enabled_for_deployment
  enabled_for_disk_encryption     = var.enabled_for_disk_encryption
  enabled_for_template_deployment = var.enabled_for_template_deployment

  # Creating Private Endpoint requires, VNet name to create a Private Endpoint
  # By default this will create a `privatelink.vault.io` DNS zone. if created in commercial cloud
  # To use existing subnet, specify `existing_subnet_id` with valid subnet id. 
  # To use existing private DNS zone specify `existing_private_dns_zone` with valid zone name
  # Private endpoints doesn't work If not using `existing_subnet_id` to create key vault inside a specified VNet.
  enable_private_endpoint = false
  existing_subnet_id      = data.azurerm_subnet.svcs_subnet.id
  virtual_network_name    = data.terraform_remote_state.landing_zone.outputs.svcs_virtual_network_name
  # existing_private_dns_zone     = "demo.example.com"

  # Current user should be here to be able to create keys and secrets
  admin_objects_ids = [
    data.azuread_group.admin_group.id
  ]

  # This is to enable resource locks for the key vault. 
  enable_resource_locks = local.enable_resource_locks

  # Tags for Azure Resources
  add_tags = {
    example = "basic deployment of key vault"
  }
}
