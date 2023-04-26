# # Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Sentinel Alert Generator
DESCRIPTION: This resource generates sentinel alerts based on the alert rules input into the module
AUTHOR/S: Curtis Slone
*/

# resource "azurerm_sentinel_alert_rule_scheduled" "sentinel_alert" {
#     for_each = var.sentinel_rule_alerts
    
# }