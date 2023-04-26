# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to connect to log analytics workspace and deploy rules
AUTHOR/S: Curtis Slone
*/

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "log_ws_onboard" {
  workspace_id = var.log_analytics_ws_id
}
