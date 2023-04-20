# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy an Azure Management Group Hierarchy for a Partner Environment
DESCRIPTION: The following components will be options in this deployment
             * Management Group Hierarchy
AUTHOR/S: jspinella
*/

########################################
###  Management Group Configuations  ###
########################################

module "mod_management_group" {  
  source            = "azurenoops/overlays-management-groups/azurerm"
  version           = "~> 1.0.0"
  root_id           = local.root_id
  root_parent_id    = data.azurerm_subscription.current.tenant_id
  root_name         = local.root_name
  management_groups = local.management_groups
}

resource "time_sleep" "after_azurerm_management_group" {
  depends_on = [
    module.mod_management_group,
  ]
  triggers = {
    "azurerm_management_group" = jsonencode(keys(module.mod_management_group))
  }

  create_duration  = local.create_duration_delay["after_azurerm_management_group"]
  destroy_duration = local.destroy_duration_delay["after_azurerm_management_group"]
}

###############################
### MG Budget Configuations ###
###############################

# This module will create a budget in the workloads management group
module "mod_mpe_mg_budgets" {  
  depends_on = [
    module.mod_management_group,
    time_sleep.after_azurerm_management_group,
  ]
  source  = "azurenoops/overlays-cost-management/azurerm//modules/budgets/managementGroup"
  version = "~> 1.0.1"

  #####################################
  ## Budget Configuration           ###
  #####################################

  budget_name       = "MPE Workloads Budget"
  budget_amount     = 14000
  budget_time_grain = "Monthly"
  budget_category   = "Cost"
  budget_scope      = module.mod_management_group.management_groups["/providers/Microsoft.Management/managementGroups/workloads"].id
  budget_time_period = {
    start_date = "2023-03-01T00:00:00Z"
    end_date   = "2024-04-01T00:00:00Z"
  }
  budget_notification = [
    {
      enabled        = true
      operator       = "GreaterThan"
      threshold      = 90
      contact_emails = var.contact_emails
    }
  ]
}
