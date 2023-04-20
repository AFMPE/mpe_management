# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy an Azure Partner Environment
DESCRIPTION: The following components will be options in this deployment
             * Hub/Spoke Network Architecture
AUTHOR/S: jspinella
*/

/* module "mod_sentinel_rule_alerts" {
  depends_on = [
    module.landing_zone
  ]
  source   = "azurenoops/overlays-sentinel-rules/azurerm//modules/scheduled-alert-rule"
  version  = "~> 1.0.0"
    
  # Sentinel Workspace Configuration
  for_each = var.sentinel_rule_alerts

  
} */