# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
  PARAMETERS
  Here are all the variables a user can override.
*/

#################################
# Global Sentinel Configuration
#################################

variable "sentinel_rule_alerts" {
  description = "A map of alerts to be created."
  type = map(object({
    display_name         = string
    description          = string
    enabled              = bool
    severity             = string
    query                = string
    query_frequency      = string
    query_period         = string
    suppression_duration = string
    suppression_enabled  = bool
    trigger_operator     = string
    trigger_threshold    = string
    action               = string
    tactics              = list(string)
    techniques           = list(string)
    grouping             = bool
    create_incident      = bool
    incident_configuration = map(object({
      lookback_duration       = string
      reopen_closed_incidents = bool
      entity_matching_method  = string
      group_by_entities       = list(string)
      group_by_alert_details  = list(string)
      group_by_custom_details = list(string)
    }))
    entity_mappings = map(object({
      entity_type_id = string
      field_mappings = list(object({
        field_name = string
        source     = string
      }))
    }))
  }))
  default = {}
}
