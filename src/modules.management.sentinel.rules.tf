# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy an Azure Partner Environment
DESCRIPTION: The following components will be options in this deployment
             * Hub/Spoke Network Architecture
AUTHOR/S: jspinella, Curtis Slone
*/


module "mod_sentinel_rule_alerts" {
  depends_on = [
    module.landing_zone
  ]
  source   = "./modules/sentinel"
  
  log_analytics_ws_id = module.landing_zone.ops_logging_workspace_id
  sentinel_rule_alerts = local.alert_rules
} 