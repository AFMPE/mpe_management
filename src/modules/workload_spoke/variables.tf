# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#######################
# Global Configuration
#######################

variable "subscription_id" {
  description = "The Azure Subscription ID where the resources in this module should be deployed."
  type        = string
}

variable "hub_virtual_network_id" {
  description = "The ID of the hub virtual network."
  type        = string
}

variable "firewall_private_ip" {
  description = "The private IP address of the firewall."
  type        = string
}

variable "location" {
  type        = string
  description = "If specified, will set the Azure region in which region bound resources will be deployed. Please see: https://azure.microsoft.com/en-gb/global-infrastructure/geographies/"
  default     = null
}

#################################
# Resource Lock Configuration
#################################

variable "enable_resource_locks" {
  type        = bool
  description = "If set to true, will enable resource locks for all resources deployed by this module where supported."
  default     = null
}

variable "lock_level" {
  description = "The level of lock to apply to the resources. Valid values are CanNotDelete, ReadOnly, or NotSpecified."
  type        = string
  default     = "CanNotDelete"
}

#################
# Workload    ###
#################

variable "wl_name" {
  description = "A name for the workload. It defaults to wl-core."
  type        = string
  default     = null
}

variable "wl_vnet_address_space" {
  description = "The address space of the workload virtual network."
  type        = list(string)
  default     = ["10.0.125.0/26"]
}

variable "wl_vnet_subnet_address_prefixes" {
  description = "The address prefixes of the workload virtual network subnets."
  type        = list(string)
  default     = ["10.0.125.0/27"]
}

variable "wl_vnet_subnet_service_endpoints" {
  description = "The service endpoints of the workload virtual network subnets."
  type        = list(string)
  default = [
    "Microsoft.KeyVault",
    "Microsoft.Sql",
    "Microsoft.Storage",
  ]
}
