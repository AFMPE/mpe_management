# # Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Sentinel Alert Generator
DESCRIPTION: This resource generates sentinel alerts based on the alert rules input into the module
AUTHOR/S: Curtis Slone
*/

resource "azurerm_sentinel_alert_rule_scheduled" "sentinel_alert" {
    
    for_each = var.sentinel_rule_alerts
    name = each.key
    log_analytics_workspace_id = var.log_analytics_ws_id
    query_frequency = each.value.query_frequency
    query_period = each.value.query_period
    severity = each.value.severity
    query = each.value.query

    dynamic "entity_mapping" {
        for_each = each.value.entity_mappings
        content {
            entity_type = entity_mapping.value.entity_type
            field_mapping {
              identifier = entity_mapping.value.identifier
              column_name = entity_mapping.value.field_name
            }
        }
    }

    tactics = each.value.tactics
    techniques = each.value.techniques
    display_name = each.value.display_name
    enabled = each.value.enabled
    

    incident_configuration {
        create_incident = each.value.create_incident

        grouping {
            enabled = each.value.grouping_configuration.enabled
            reopen_closed_incident = each.value.grouping_configuration.reopen_closed_incident
            lookback_duration = each.value.grouping_configuration.lookback_duration
        }
    }

    suppression_duration = each.value.suppression_duration
    suppression_enabled = each.value.suppression_enabled
    event_grouping = each.value.event_grouping
}