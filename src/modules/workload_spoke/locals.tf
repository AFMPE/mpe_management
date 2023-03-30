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
  subscription_id          = var.subscription_id
  org_name                 = var.required.org_name
  deploy_environment       = var.required.deploy_environment
  environment              = var.required.environment
  metadata_host            = var.required.metadata_host
  enable_resource_locks    = var.enable_resource_locks
  default_location         = var.location
  default_tags             = var.default_tags
}

# The following locals are used to landing Zone - Partner Environment - Spokes
locals {
  # The following locals are used to define the spoke resources
  deployed_to_hub_subscription = false
  deny_all_inbound             = false

  # The following locals are used to define the ops resources
  wl_name                     = var.wl_name
  wl_vnet_address_space       = var.wl_vnet_address_space
  wl_subnet_addresses         = var.wl_vnet_subnet_address_prefixes
  wl_vnet_subnets             = {}
  wl_subnet_service_endpoints = var.wl_vnet_subnet_service_endpoints
  wl_nsg_rules = [
    {
      name                       = "Allow-Traffic-From-Spokes"
      priority                   = 200
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "*"
      source_port_range          = "*"
      destination_port_ranges    = ["22", "80", "443", "3389"]
      source_address_prefixes    = ["10.0.120.0/26", "10.0.115.0/26"]
      destination_address_prefix = var.wl_vnet_address_space
    },
  ]
}
