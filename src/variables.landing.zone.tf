# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
  PARAMETERS
  Here are all the variables a user can override.
*/

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

variable "svcs_pe_subnet_address_prefixes" {
  description = "The address prefixes of the svcs virtual network private endpoint subnets."
  type        = list(string)
  default     = null
}

variable "svcs_vnet_subnet_service_endpoints" {
  description = "The service endpoints of the svcs virtual network subnets."
  type        = list(string)
  default = null
}
