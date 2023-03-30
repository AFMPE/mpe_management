# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

variable "service_alerts" {
  type = list(object({
    alert_name        = string
    alert_scope       = string
    alert_description = string
    alert_severity    = string
    alert_status      = string
    alert_impact      = string
    alert_service     = string
    alert_region      = string
    alert_start_time  = string
    alert_end_time    = string
  }))
  default = []
}