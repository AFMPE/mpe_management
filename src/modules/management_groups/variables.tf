# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
  PARAMETERS
  Here are all the variables a user can override.
*/

#################################
# Global Configuration
#################################
variable "root_management_group_id" {
  type        = string
  description = "If specified, will set a custom Name (ID) value for the \"root\" Management Group, and append this to the ID for all core Management Groups."
  default     = "ampe"

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]{2,10}$", var.root_management_group_id))
    error_message = "Value must be between 2 to 10 characters long, consisting of alphanumeric characters and hyphens."
  }
}

variable "root_management_group_display_name" {
  type        = string
  description = "If specified, will set a custom Display Name value for the \"root\" Management Group."
  default     = "ampe"

  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9- ._]{1,22}[A-Za-z0-9]?$", var.root_management_group_display_name))
    error_message = "Value must be between 2 to 24 characters long, start with a letter, end with a letter or number, and can only contain space, hyphen, underscore or period characters."
  }
}

variable "subscription_id_hub" {
  type        = string
  description = "If specified, identifies the Platform subscription for \"Hub\" for resource deployment and correct placement in the Management Group hierarchy."

  validation {
    condition     = can(regex("^[a-z0-9-]{36}$", var.subscription_id_hub)) || var.subscription_id_hub == ""
    error_message = "Value must be a valid Subscription ID (GUID)."
  }
}

variable "subscription_id_identity" {
  type        = string
  description = "If specified, identifies the Platform subscription for \"Identity\" for resource deployment and correct placement in the Management Group hierarchy."
}

variable "subscription_id_operations" {
  type        = string
  description = "If specified, identifies the Platform subscription for \"Operations\" for resource deployment and correct placement in the Management Group hierarchy."
}

variable "subscription_id_sharedservices" {
  type        = string
  description = "If specified, identifies the Platform subscription for \"Shared Services\" for resource deployment and correct placement in the Management Group hierarchy."
}

variable "subscription_id_partners_dev" {
  type        = string
  description = "If specified, identifies the Partners subscription for \"Partners Dev\" for resource deployment and correct placement in the Management Group hierarchy."
}

variable "subscription_id_partners_prod" {
  type        = string
  description = "If specified, identifies the Partners subscription for \"Partners Prod\" for resource deployment and correct placement in the Management Group hierarchy."
}

variable "subscription_id_internal" {
  type        = string
  description = "If specified, identifies the Imternal subscription for \"Internal\" for resource deployment and correct placement in the Management Group hierarchy."
}

variable "subscription_id_sandbox" {
  type        = string
  description = "If specified, identifies the Sandbox subscription for \"Sandbox\" for resource deployment and correct placement in the Management Group hierarchy."
}

##########################
# Policy Configuration  ##
##########################

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

##########################
# Budget Configuration  ##
##########################

variable "contact_emails" {
  type        = list(string)
  description = "The list of email addresses to be used for contact information for the policy assignments."
  default     = ["mpe@microsoft.com"]
}

