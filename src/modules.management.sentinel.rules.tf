# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy an Azure Partner Environment
DESCRIPTION: The following components will be options in this deployment
             * Hub/Spoke Network Architecture
AUTHOR/S: jspinella, Curtis Slone
*/

data "azurerm_log_analytics_workspace" "current" {
  name                = "ampe-eus-ops-logging-core-test-log"
  resource_group_name = "ampe-eus-ops-logging-core-test-rg"
}

module "mod_sentinel_rule_alerts" {
  depends_on = [
    module.landing_zone
  ]
  source   = "./modules/sentinel"
  
  log_analytics_ws_id = data.azurerm_log_analytics_workspace.current.id
  # sentinel_rule_alerts = local.alert_rules
} 