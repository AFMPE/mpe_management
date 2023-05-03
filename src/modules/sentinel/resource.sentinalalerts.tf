# # Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Sentinel Alert Generator
DESCRIPTION: This resource generates sentinel alerts based on the alert rules input into the module
AUTHOR/S: Curtis Slone
*/

/* module "sentinel_rules" {
  source  = "azurenoops/overlays-sentinel-rules/azurerm//modules/scheduled-alert-rule"
  version = ">= 0.1.0"

  for_each                   = var.sentinel_rule_alerts
  enabled                    = each.value.enabled
  name                       = each.value.key
  display_name               = each.value.display_name
  log_analytics_workspace_id = var.log_analytics_ws_id
  query_frequency            = each.value.query_frequency
  query_period               = each.value.query_period
  severity                   = each.value.severity
  query                      = each.value.query
  entity_mapping             = each.value.entity_mappings
  action                     = each.value.action
  suppression_duration       = each.value.suppression_duration
  suppression_enabled        = each.value.suppression_enabled
  event_grouping             = each.value.event_grouping
  tactics                    = each.value.tactics
  techniques                 = each.value.techniques
  description                = each.value.description
  create_incident            = each.value.create_incident
  grouping                   = each.value.grouping
  incident_configuration     = each.value.incident_configuration
  entity_mappings            = each.value.entity_mappings
  trigger_operator           = each.value.trigger_operator
  trigger_threshold          = each.value.trigger_threshold

} */

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
            enabled = each.value.grouping_enabled
            reopen_closed_incidents = each.value.reopen_closed_incidents
            lookback_duration = each.value.lookback_duration
            entity_matching_method = each.value.entity_matching_method
            group_by_entities = each.value.group_by_entities
            group_by_alert_details = each.value.group_by_alert_details
        }
    }

    suppression_duration = each.value.suppression_duration
    suppression_enabled = each.value.suppression_enabled

    event_grouping {
      aggregation_method = each.value.event_grouping
    }
}
