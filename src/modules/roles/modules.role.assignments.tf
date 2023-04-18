# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy Custom Role Assignments for Azure Policy in Partner Environments
DESCRIPTION: The following components will be options in this deployment
             * Custom Role Assignments
AUTHOR/S: jspinella
*/

#############################################
### Custom Role Assignments Configuations ###
#############################################
/* resource "azurerm_role_assignment" "network_operations" {
  # Special handling of OPTIONAL name to ensure consistent and correct
  # mapping of Terraform state ADDR value to Azure Resource ID value.
  name = "00000000-0000-0000-0000-000000000000"

  # Mandatory resource attributes
  scope        = "providers/Microsoft.Management/managementGroups/${local.root_id}"
  principal_id = "00000000-0000-0000-0000-000000000000"

  # Optional resource attributes
  role_definition_name = "Custom - NoOps"
  role_definition_id   = azurerm_role_definition.network_operations.id

  # Set explicit dependency on Management Group, Policy, and Role Definition deployments
  depends_on = [
    time_sleep.after_azurerm_management_group,
    time_sleep.after_azurerm_role_definition,
  ]

}

resource "azurerm_role_assignment" "platform_operations" {
  # Special handling of OPTIONAL name to ensure consistent and correct
  # mapping of Terraform state ADDR value to Azure Resource ID value.
  name = "00000000-0000-0000-0000-000000000000"

  # Mandatory resource attributes
  scope        = "providers/Microsoft.Management/managementGroups/${local.root_id}"
  principal_id = "00000000-0000-0000-0000-000000000000"

  # Optional resource attributes
  role_definition_name = "Custom - NoOps"
  role_definition_id   = azurerm_role_definition.platform_operations.id

  # Set explicit dependency on Management Group, Policy, and Role Definition deployments
  depends_on = [
    time_sleep.after_azurerm_management_group,
    time_sleep.after_azurerm_role_definition,
  ]

}

resource "time_sleep" "after_azurerm_role_assignment" {
  depends_on = [
    time_sleep.after_azurerm_management_group,
    time_sleep.after_azurerm_role_definition,
    azurerm_role_assignment.network_operations,
    azurerm_role_assignment.platform_operations,
    module.role_assignments_for_policy,
  ]

  triggers = {
    "azurerm_role_assignment_noops" = jsonencode(keys(azurerm_role_assignment.network_operations)),
    "azurerm_role_assignment_noops" = jsonencode(keys(azurerm_role_assignment.platform_operations)),
    "azurerm_role_assignment_noops" = jsonencode(keys(module.role_assignments_for_policy))
  }

  create_duration  = local.create_duration_delay["after_azurerm_role_assignment"]
  destroy_duration = local.destroy_duration_delay["after_azurerm_role_assignment"]
}
 */