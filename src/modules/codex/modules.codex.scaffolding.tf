# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to to create scaffolding for the SCCA Compliant Mission Partner Environment
*/

module "mod_codex_rg" {
  source  = "azurenoops/overlays-resource-group/azurerm"
  version = ">= 1.0.1"

  location                = local.location
  use_location_short_name = var.use_location_short_name # Use the short location name in the resource group name
  org_name                = local.org_name
  environment             = local.deploy_environment
  workload_name           = local.workload_name
  custom_rg_name          = null

  // Tags
  add_tags = merge(local.hub_resources_tags,)
}