# # Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Sentinel Alert Generator
DESCRIPTION: This resource generates sentinel alerts based on the alert rules input into the module
AUTHOR/S: Curtis Slone
*/

resource "azurerm_sentinel_alert_rule_scheduled" "sentinel_alert" {
    
    for_each = local.alert_rules
    name = each.key
    log_analytics_workspace_id = var.log_analytics_ws_id
    query_frequency = each.value.query_frequency
    query_period = each.value.query_period
    severity = each.value.severity
    query = each.value.query

    # https://faultbucket.ca/2020/09/terraform-nested-for_each-example/
    dynamic "entity_mapping" {
      
    }
}