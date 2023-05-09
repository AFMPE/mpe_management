# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to to create scaffolding for the SCCA Compliant Mission Partner Environment
*/

#---------------------------------------------------------
# Azure Region Lookup
#----------------------------------------------------------
module "mod_azure_region_lookup" {
  source  = "azurenoops/overlays-azregions-lookup/azurerm"
  version = ">= 1.0.0"

  azure_region  = var.location
}

module "mod_codex_rg" {
  source  = "azurenoops/overlays-resource-group/azurerm"
  version = ">= 1.0.1"

  count = var.create_resource_group ? 1 : 0

  location                = module.mod_azregions.location_cli
  use_location_short_name = var.use_location_short_name # Use the short location name in the resource group name
  org_name                = local.org_name
  environment             = local.deploy_environment
  workload_name           = local.workload_name
  custom_rg_name          = null

  // Tags
  add_tags = merge(local.hub_resources_tags,)
}