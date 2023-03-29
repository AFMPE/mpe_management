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
  root_id                  = var.root_management_group_id
  root_name                = var.root_management_group_display_name
  subscription_id_hub      = var.subscription_id_hub
  subscription_id_sandbox  = var.subscription_id_sandbox
  subscription_id_internal = var.subscription_id_internal
  subscription_id_partners_dev = var.subscription_id_partners_dev
  subscription_id_partners_prod = var.subscription_id_partners_prod
}


# The following locals are used to define the hub resources
locals {
  management_groups = {
    platforms = {
      display_name               = "platforms"
      management_group_name      = "platforms"
      parent_management_group_id = "${local.root_id}"
      subscription_ids           = []
    },
    workloads = {
      display_name               = "workloads"
      management_group_name      = "workloads"
      parent_management_group_id = "${local.root_id}"
      subscription_ids           = []
    },
    sandbox = {
      display_name               = "sandbox"
      management_group_name      = "sandbox"
      parent_management_group_id = "${local.root_id}"
      subscription_ids           = ["${local.subscription_id_sandbox}"]
    },
    transport = {
      display_name               = "transport"
      management_group_name      = "transport"
      parent_management_group_id = "platforms"
      subscription_ids           = ["${local.subscription_id_hub}"]
    },
    internal = {
      display_name               = "internal"
      management_group_name      = "internal"
      parent_management_group_id = "workloads"
      subscription_ids           = ["${local.subscription_id_internal}"]
    }
    partners = {
      display_name               = "partners"
      management_group_name      = "partners"
      parent_management_group_id = "workloads"
      subscription_ids           = ["${local.subscription_id_partners_dev}", "${local.subscription_id_partners_prod}"]
    }
  }
}

# The following locals are used to define base Azure
# provider paths and resource types
locals {
  provider_path = {
    management_groups = "/providers/Microsoft.Management/managementGroups/"
    role_assignment   = "/providers/Microsoft.Authorization/roleAssignments/"
  }  
}

# The following locals are used to control time_sleep
# delays between resources to reduce transient errors
# relating to replication delays in Azure
locals {
  create_duration_delay = {
    after_azurerm_management_group = var.create_duration_delay["azurerm_management_group"]
  }
  destroy_duration_delay = {
    after_azurerm_management_group = var.destroy_duration_delay["azurerm_management_group"]
  }
}
