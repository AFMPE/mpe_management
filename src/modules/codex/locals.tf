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
  subscription_id_hub      = var.subscription_id_hub
  org_name                 = var.required.org_name
  deploy_environment       = var.required.deploy_environment
  environment              = var.required.environment
  metadata_host            = var.required.metadata_host
  enable_resource_locks    = var.enable_resource_locks
  default_location         = var.location
  default_tags             = var.default_tags  
  disable_telemetry        = var.disable_telemetry
}

# The following locals are used to define a set of module
# tags applied to all resources unless disabled by the
# input variable "disable_module_tags" and prepare the
# tag blocks for each sub-module
locals {
  base_module_tags = {
    deployedBy = "AzureNoOpsTF"
  }
  hub_resources_tags = merge(local.base_module_tags,
    local.default_tags,
  )  
}
