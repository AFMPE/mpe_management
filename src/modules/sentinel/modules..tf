 # Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy an Azure Sentinel Workspace and Azure Sentinel Solutions
DESCRIPTION: The following components will be options in this deployment
               
AUTHOR/S: jspinella
*/

/* resource "azurerm_sentinel_data_connector_microsoft_threat_protection" "main" {
  name                       = "mtp"
  log_analytics_workspace_id = module.mod_operational_logging.laws_resource_id
}

resource "azurerm_sentinel_data_connector_azure_security_center" "main" {
  name                       = "asc"
  log_analytics_workspace_id = module.mod_operational_logging.laws_resource_id
}

resource "azurerm_sentinel_data_connector_azure_advanced_threat_protection" "main" {
  name                       = "atp"
  log_analytics_workspace_id = module.mod_operational_logging.laws_resource_id
}

resource "azurerm_sentinel_data_connector_azure_activity_log" "main" {
  name                       = "activity"
  log_analytics_workspace_id = module.mod_operational_logging.laws_resource_id
} */