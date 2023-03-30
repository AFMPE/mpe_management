# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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

#################
# Workload    ###
#################

variable "wl_name" {
  description = "A name for the workload. It defaults to wl-core."
  type        = string
  default     = "wl-core"
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
