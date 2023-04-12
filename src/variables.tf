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

################################
# Landing Zone Configuration  ##
################################

##################
# Ops Logging  ###
##################

variable "ops_logging_name" {
  description = "A name for the ops logging. It defaults to ops-logging-core."
  type        = string
  default     = null
}

variable "enable_sentinel" {
  description = "Enables an Azure Sentinel Log Analytics Workspace Solution"
  type        = bool
  default     = null
}

variable "log_analytics_workspace_sku" {
  description = "The SKU of the Log Analytics Workspace. Possible values are PerGB2018 and Free. Default is PerGB2018."
  type        = string
  default     = null
}

variable "log_analytics_logs_retention_in_days" {
  description = "The number of days to retain logs for. Possible values are between 30 and 730. Default is 30."
  type        = number
  default     = null
}

##########
# Hub  ###
##########

variable "hub_name" {
  description = "A name for the hub. It defaults to hub-core."
  type        = string
  default     = null
}

variable "hub_vnet_address_space" {
  description = "The address space of the hub virtual network."
  type        = list(string)
  default     = null
}

variable "hub_vnet_subnet_address_prefixes" {
  description = "The address prefixes of the hub virtual network subnets."
  type        = list(string)
  default     = null
}

variable "hub_vnet_subnet_service_endpoints" {
  description = "The service endpoints of the hub virtual network subnets."
  type        = list(string)
  default = null
}

variable "firewall_supernet_IP_address" {
  description = "The IP address of the firewall supernet."
  type        = string
  default     = null
}

variable "enable_firewall" {
  description = "Enables an Azure Firewall"
  type        = bool
  default     = null
}

variable "enable_force_tunneling" {
  description = "Enables Force Tunneling for Azure Firewall"
  type        = bool
  default     = null
}

variable "enable_bastion_host" {
  description = "Enables an Azure Bastion Host"
  type        = bool
  default     = null
}

#################
# Operations  ###
#################

variable "ops_name" {
  description = "A name for the ops. It defaults to ops-core."
  type        = string
  default     = null
}

variable "ops_vnet_address_space" {
  description = "The address space of the ops virtual network."
  type        = list(string)
  default     = null
}

variable "ops_vnet_subnet_address_prefixes" {
  description = "The address prefixes of the ops virtual network subnets."
  type        = list(string)
  default     = null
}

variable "ops_vnet_subnet_service_endpoints" {
  description = "The service endpoints of the ops virtual network subnets."
  type        = list(string)
  default = null
}

######################
# Shared Services  ###
######################

variable "svcs_name" {
  description = "A name for the svcs. It defaults to svcs-core."
  type        = string
  default     = null
}

variable "svcs_vnet_address_space" {
  description = "The address space of the svcs virtual network."
  type        = list(string)
  default     = null
}

variable "svcs_vnet_subnet_address_prefixes" {
  description = "The address prefixes of the svcs virtual network subnets."
  type        = list(string)
  default     = null
}

variable "svcs_vnet_subnet_service_endpoints" {
  description = "The service endpoints of the svcs virtual network subnets."
  type        = list(string)
  default = null
}
