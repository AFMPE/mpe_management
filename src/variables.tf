# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
  PARAMETERS
  Here are all the variables a user can override.
*/

#################################
# Global Configuration
#################################

variable "required" {
  description = "A map of required variables for the deployment"
  default = {
    org_name           = "ampe"
    deploy_environment = "dev"
    environment        = "public"
    metadata_host      = "management.azure.com"
  }
}

variable "default_location" {
  type        = string
  description = "If specified, will set the Azure region in which region bound resources will be deployed. Please see: https://azure.microsoft.com/en-gb/global-infrastructure/geographies/"
  default     = "eastus"
}

variable "default_tags" {
  type        = map(string)
  description = "If specified, will set the default tags for all resources deployed by this module where supported."
  default     = {}
}

variable "disable_base_module_tags" {
  type        = bool
  description = "If set to true, will remove the base module tags applied to all resources deployed by the module which support tags."
  default     = false
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
  default     = null
}

variable "subscription_id_operations" {
  type        = string
  description = "If specified, identifies the Platform subscription for \"Operations\" for resource deployment and correct placement in the Management Group hierarchy."
  default     = null
}

variable "subscription_id_sharedservices" {
  type        = string
  description = "If specified, identifies the Platform subscription for \"Shared Services\" for resource deployment and correct placement in the Management Group hierarchy."
  default     = null
}

variable "subscription_id_partners_gsa_dev" {
  type        = string
  description = "If specified, identifies the Partners GSA subscription for \"Partners Dev\" for resource deployment and correct placement in the Management Group hierarchy."
}

variable "subscription_id_partners_gsa_prod" {
  type        = string
  description = "If specified, identifies the Partners GSA subscription for \"Partners Prod\" for resource deployment and correct placement in the Management Group hierarchy."
}

variable "subscription_id_internal" {
  type        = string
  description = "If specified, identifies the Imternal subscription for \"Internal\" for resource deployment and correct placement in the Management Group hierarchy."
}

variable "subscription_id_sandbox" {
  type        = string
  description = "If specified, identifies the Sandbox subscription for \"Sandbox\" for resource deployment and correct placement in the Management Group hierarchy."
}

#################################
# Remote State Configuration
#################################

## This is required for retrieving state
variable "state_sa_name" {
  type        = string
  description = "The name of the storage account to use for storing the Terraform state."
}

variable "state_sa_container_name" {
  type        = string
  description = "The name of the container to use for storing the Terraform state."
}

# Storage Account Resource Group
variable "state_sa_rg" {
  type        = string
  description = "The name of the resource group in which the storage account is located."
}

#################################
# Resource Lock Configuration
#################################

variable "enable_resource_locks" {
  type        = bool
  description = "If set to true, will enable resource locks for all resources deployed by this module where supported."
  default     = false
}

variable "lock_level" {
  description = "The level of lock to apply to the resources. Valid values are CanNotDelete, ReadOnly, or NotSpecified."
  type        = string
  default     = "CanNotDelete"
}

###################################
# Service Alerts Configuration  ##
###################################

variable "contact_email" {
  description = "Email address for alert notifications"
  type        = string
  default     = ""
}
##########################
# Duration Configuration ##
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

