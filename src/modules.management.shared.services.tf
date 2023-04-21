# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy an Azure Partner Environment
DESCRIPTION: The following components will be options in this deployment
             * Shared Services
               * VM Jumpbox
               * Key Vault
AUTHOR/S: jspinella
*/

################################
### Hub/Spoke Configuations  ###
################################

module "shared_services" {
  source = "./modules/shared_services"

  # Global Configuration
  required                = var.required
  location                = var.default_location
  state_sa_rg             = local.state_sa_rg
  state_sa_name           = local.state_sa_name
  state_sa_container_name = local.state_sa_container_name

  # Key Vault Configuration
  enabled_for_deployment          = local.enabled_for_deployment
  enabled_for_disk_encryption     = local.enabled_for_disk_encryption
  enabled_for_template_deployment = local.enabled_for_template_deployment

  # Bastion VM Configuration
}
