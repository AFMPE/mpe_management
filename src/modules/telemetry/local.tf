# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# The following block of locals are used to avoid using
# empty object types in the code
locals {
  empty_list   = []
  empty_map    = tomap({})
  empty_string = ""
}

# The following locals are used to convert provided input
# variables to locals before use elsewhere in the module
locals {
  root_id                        = var.root_management_group_id
  root_name                      = var.root_management_group_display_name
  subscription_id_hub            = var.subscription_id_hub
  org_name                       = var.required.org_name
  deploy_environment             = var.required.deploy_environment
  environment                    = var.required.environment
  metadata_host                  = var.required.metadata_host
  enable_resource_locks          = var.enable_resource_locks
  default_location               = var.default_location
  default_tags                   = var.default_tags
  disable_base_module_tags       = var.disable_base_module_tags
  disable_telemetry              = var.disable_telemetry
}

# The following locals are used to ensure non-null values
# are assigned to each of the corresponding inputs for
# correct processing in `lookup()` functions.
#
# We also need to ensure that each `???_resources_advanced`
# local is handled as an `object()` rather than `map()` to
# prevent `lookup()` errors when only partially specified
# with attributes of a single type.
#
# This is achieved by merging an `object()` with multiple
# types (`create_object`) to the input from `advanced`.
#
# For more information about this error, see:
# https://github.com/Azure//issues/227#issuecomment-1097623677
locals {
  enforcement_mode_default = {
    enforcement_mode = null
  }
  create_object = {
    # Technically only needs two object types to work.
    add_bool   = true
    add_string = local.empty_string
    add_list   = local.empty_list
    add_map    = local.empty_map
    add_null   = null
  }
  parameter_map_default = {
    parameters = local.empty_map
  }
}

# The following locals are used to define a set of module
# tags applied to all resources unless disabled by the
# input variable "disable_module_tags" and prepare the
# tag blocks for each sub-module
locals {
  base_module_tags = {
    deployedBy = "AzureNoOpsTF"
  }
  hub_resources_tags = merge(
    local.disable_base_module_tags ? local.empty_map : local.base_module_tags,
    local.default_tags,
  )
  operations_resources_tags = merge(
    local.disable_base_module_tags ? local.empty_map : local.base_module_tags,
    local.default_tags,
  )
  sharedservices_resources_tags = merge(
    local.disable_base_module_tags ? local.empty_map : local.base_module_tags,
    local.default_tags,
  )
}

# The following locals are used to define base Azure
# provider paths and resource types
locals {
  provider_path = {
    management_groups = "/providers/Microsoft.Management/managementGroups/"
    role_assignment   = "/providers/Microsoft.Authorization/roleAssignments/"
  }  
}

# The following locals are used to define RegEx
# patterns used within this module
locals {
  # The following regex is designed to consistently
  # split a resource_id into the following capture
  # groups, regardless of resource type:
  # [0] Resource scope, type substring (e.g. "/providers/Microsoft.Management/managementGroups/")
  # [1] Resource scope, name substring (e.g. "group1")
  # [2] Resource, type substring (e.g. "/providers/Microsoft.Authorization/policyAssignments/")
  # [3] Resource, name substring (e.g. "assignment1")
  regex_split_resource_id         = "(?i)((?:/[^/]+){0,8}/)?([^/]+)?((?:/[^/]+){3}/)([^/]+)$"
  regex_scope_is_management_group = "(?i)(/providers/Microsoft.Management/managementGroups/)([^/]+)$"
  # regex_scope_is_subscription     = "(?i)(/subscriptions/)([^/]+)$"
  # regex_scope_is_resource_group   = "(?i)(/subscriptions/[^/]+/resourceGroups/)([^/]+)$"
  # regex_scope_is_resource         = "(?i)(/subscriptions/[^/]+/resourceGroups(?:/[^/]+){4}/)([^/]+)$"
}

# The following locals are used to control time_sleep
# delays between resources to reduce transient errors
# relating to replication delays in Azure
locals {
  create_duration_delay = {
    after_azurerm_management_group      = var.create_duration_delay["azurerm_management_group"]
    after_azurerm_role_assignment       = var.create_duration_delay["azurerm_role_assignment"]
    after_azurerm_role_definition       = var.create_duration_delay["azurerm_role_definition"]
  }
  destroy_duration_delay = {
    after_azurerm_management_group      = var.destroy_duration_delay["azurerm_management_group"]
    after_azurerm_role_assignment       = var.destroy_duration_delay["azurerm_role_assignment"]
    after_azurerm_role_definition       = var.create_duration_delay["azurerm_role_definition"]
  }
}

# Telemetry is collected by creating an empty ARM deployment with a specific name
# If you want to disable telemetry, you can set the disable_telemetry variable to true

# The following locals identify the module
locals {
  # PUID identifies the module
  telem_management_puid = "34603aac-98f8-4a55-92fc-4c78378c9ba5"
}

# The following `can()` is used for when disable_telemetry = true
locals {
  telem_random_hex = can(random_id.telem[0].hex) ? random_id.telem[0].hex : local.empty_string
}

# Here we create the ARM templates for the telemetry deployment
locals {
  telem_arm_subscription_template_content = <<TEMPLATE
{
  "$schema": "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {},
  "variables": {},
  "resources": [],
  "outputs": {
    "telemetry": {
      "type": "String",
      "value": "For more information, see https://aka.ms/azurenoops/tf/telemetry"
    }
  }
}
TEMPLATE
}
