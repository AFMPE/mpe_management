# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#---------------------------------------------------------
# CodeX Storage Account Creation
#----------------------------------------------------------
module "codex_loganalytics_sa" {
  source                   = "azurenoops/overlays-storage-account/azurerm"
  version                  = ">= 0.1.0"
  depends_on               = [module.mod_codex_rg]
  resource_group_name      = module.mod_codex_rg.resource_group_name
  location                 = local.location
  org_name                 = local.org_name
  environment              = local.environment
  deploy_environment       = local.deploy_environment
  workload_name            = local.workload_name
  account_kind             = "StorageV2"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  # Locks
  enable_resource_locks = var.enable_resource_locks
  add_tags              = merge(local.hub_resources_tags, )
}