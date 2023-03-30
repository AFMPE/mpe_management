# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy Service Alerts for Azure Service Health in Partner Environments
DESCRIPTION: The following components will be options in this deployment
             * Service Alerts
AUTHOR/S: jspinella
*/

###################################
### Service Alert Configuations ###
###################################

# This module will create a outage service alert in the workloads management group
module "mod_root_outage_service_alert" {
  for_each =  var.service_alerts
  source            = "azurenoops/overlays-service-health/azurerm//modules/serviceAlert"
  version           = "~> 1.0.0"
  alert_name        = each.value.alert_name
  alert_scope       = each.value.alert_scope
  alert_description = each.value.alert_description
  alert_severity    = each.value.alert_severity
  alert_status      = each.value.alert_status
  alert_impact      = each.value.alert_impact
  alert_service     = each.value.alert_service
  alert_region      = each.value.alert_region
  alert_start_time  = each.value.alert_start_time
  alert_end_time    = each.value.alert_end_time
}
