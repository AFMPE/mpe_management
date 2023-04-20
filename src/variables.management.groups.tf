# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
  PARAMETERS
  Here are all the variables a user can override.
*/

#################################
# Global Configuration
#################################

variable "enable_management_groups" {
  description = "Enable Management Groups"
  type        = bool
  default     = false
}

variable "root_management_group_id" {
  type        = string
  description = "If specified, will set a custom Name (ID) value for the \"root\" Management Group, and append this to the ID for all core Management Groups."

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]{2,10}$", var.root_management_group_id))
    error_message = "Value must be between 2 to 10 characters long, consisting of alphanumeric characters and hyphens."
  }
}

variable "root_management_group_display_name" {
  type        = string
  description = "If specified, will set a custom Display Name value for the \"root\" Management Group."

  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9- ._]{1,22}[A-Za-z0-9]?$", var.root_management_group_display_name))
    error_message = "Value must be between 2 to 24 characters long, start with a letter, end with a letter or number, and can only contain space, hyphen, underscore or period characters."
  }
}

####################################
# Management Group Configuration  ##
####################################

variable "management_groups" {
  type = any
  description = "A list of Management Groups to create."
  default = {
    platforms = {
      display_name               = "platforms"
      management_group_name      = "platforms"
      parent_management_group_id = "${var.root_management_group_id}"
      subscription_ids           = []
    },
    workloads = {
      display_name               = "workloads"
      management_group_name      = "workloads"
      parent_management_group_id = "${var.root_management_group_id}"
      subscription_ids           = []
    },
    sandbox = {
      display_name               = "sandbox"
      management_group_name      = "sandbox"
      parent_management_group_id = "${var.root_management_group_id}"
      subscription_ids           = ["${var.subscription_id_sandbox}"]
    },
    transport = {
      display_name               = "transport"
      management_group_name      = "transport"
      parent_management_group_id = "platforms"
      subscription_ids           = ["${var.subscription_id_hub}"]
    },
    internal = {
      display_name               = "internal"
      management_group_name      = "internal"
      parent_management_group_id = "workloads"
      subscription_ids           = ["${var.subscription_id_internal}"]
    }
    partners = {
      display_name               = "partners"
      management_group_name      = "partners"
      parent_management_group_id = "workloads"
      subscription_ids           = ["${var.subscription_id_gsa_dev}", "${var.subscription_id_gsa_prod}"]
    }
  }  
}

###########################
# Duration Configuration ##
###########################

variable "create_duration_delay" {
  type = object({
    azurerm_management_group = optional(string, "30s")
    azurerm_role_assignment  = optional(string, "0s")
    azurerm_role_definition  = optional(string, "60s")
  })
  description = "Used to tune terraform apply when faced with errors caused by API caching or eventual consistency. Sets a custom delay period after creation of the specified resource type."
  default = {
    azurerm_management_group = "30s"
    azurerm_role_assignment  = "0s"
    azurerm_role_definition  = "60s"
  }

  validation {
    condition     = can([for v in values(var.create_duration_delay) : regex("^[0-9]{1,6}(s|m|h)$", v)])
    error_message = "The create_duration_delay values must be a string containing the duration in numbers (1-6 digits) followed by the measure of time represented by s (seconds), m (minutes), or h (hours)."
  }
}

variable "destroy_duration_delay" {
  type = object({
    azurerm_management_group = optional(string, "0s")
    azurerm_role_assignment  = optional(string, "0s")
    azurerm_role_definition  = optional(string, "0s")
  })
  description = "Used to tune terraform deploy when faced with errors caused by API caching or eventual consistency. Sets a custom delay period after destruction of the specified resource type."
  default = {
    azurerm_management_group = "0s"
    azurerm_role_assignment  = "0s"
    azurerm_role_definition  = "0s"
  }

  validation {
    condition     = can([for v in values(var.destroy_duration_delay) : regex("^[0-9]{1,6}(s|m|h)$", v)])
    error_message = "The destroy_duration_delay values must be a string containing the duration in numbers (1-6 digits) followed by the measure of time represented by s (seconds), m (minutes), or h (hours)."
  }
}