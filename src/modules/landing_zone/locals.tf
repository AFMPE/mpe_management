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
  disable_base_module_tags = var.disable_base_module_tags
  disable_telemetry        = var.disable_telemetry
}

# The following locals are used to define RegEx
# patterns used within this module
locals {
  # The following regex is designed to consistently
  # split a resource_id into the following capture
  # groups, regardless of resource type:
  # [0] Resource scope, type substring (e.g. "/providers/Microsoft.Management/managementGroups/")
  # [1] Resource scope, name substring (e.g. "group1")
  # [2] Resource, type substring (e.g. "/providers/Microsoft.Authorization/policyAssignments/")
  # [3] Resource, name substring (e.g. "assignment1")
  regex_split_resource_id         = "(?i)((?:/[^/]+){0,8}/)?([^/]+)?((?:/[^/]+){3}/)([^/]+)$"
  regex_scope_is_management_group = "(?i)(/providers/Microsoft.Management/managementGroups/)([^/]+)$"
  # regex_scope_is_subscription     = "(?i)(/subscriptions/)([^/]+)$"
  # regex_scope_is_resource_group   = "(?i)(/subscriptions/[^/]+/resourceGroups/)([^/]+)$"
  # regex_scope_is_resource         = "(?i)(/subscriptions/[^/]+/resourceGroups(?:/[^/]+){4}/)([^/]+)$"
}

# The following locals are used to define a set of module
# tags applied to all resources unless disabled by the
# input variable "disable_module_tags" and prepare the
# tag blocks for each sub-module
locals {
  base_module_tags = {
    deployedBy = "AzureNoOpsTF"
  }
  hub_resources_tags = merge(
    local.disable_base_module_tags ? local.empty_map : local.base_module_tags,
    local.default_tags,
  )
  operations_resources_tags = merge(
    local.disable_base_module_tags ? local.empty_map : local.base_module_tags,
    local.default_tags,
  )
  sharedservices_resources_tags = merge(
    local.disable_base_module_tags ? local.empty_map : local.base_module_tags,
    local.default_tags,
  )
}

# The following locals are used to landing Zone - Partner Environment - Ops Logging
locals {
  ops_logging_name            = var.ops_logging_name
  enable_sentinel             = var.enable_sentinel
  log_analytics_workspace_sku = var.log_analytics_workspace_sku
  log_analytics_retention     = var.log_analytics_logs_retention_in_days
  security_center_contacts = {
    email               = "john.doe@microsoft.com" # must be a valid email address
    phone               = "5555555555"             # Optional
    alert_notifications = true
    alerts_to_admins    = true
  }
}

# The following locals are used to landing Zone - Partner Environment - Hub
locals {
  # The following locals are used to define the hub resources
  hub_name               = var.hub_name
  hub_vnet_address_space = var.hub_vnet_address_space
  create_ddos_plan       = false
  create_network_watcher = true
  hub_subnet_addresses   = var.hub_vnet_subnet_address_prefixes
  hub_vnet_subnets = {
    "dmz_Subnet" = {
      name                                       = "dmz"
      address_prefixes                           = ["10.0.100.192/27"]
      service_endpoints                          = ["Microsoft.Storage", "Microsoft.KeyVault"]
      private_endpoint_network_policies_enabled  = true
      private_endpoint_service_endpoints_enabled = false
    }
  }
  hub_subnet_service_endpoints = var.hub_vnet_subnet_service_endpoints
  hub_deny_all_inbound         = false

  # The following locals are used to define the firewall for the hub resources
  enable_firewall         = var.enable_firewall
  enable_forced_tunneling = var.enable_force_tunneling

  firewall_config = {
    sku_name          = "AZFW_VNet"
    sku_tier          = "Premium"
    threat_intel_mode = "Alert"
  }

  fw_client_snet_address_prefixes     = ["10.0.100.0/26"]
  fw_management_snet_address_prefixes = ["10.0.100.64/26"]
  fw_supernet_IP_address              = "10.96.0.0/19"

  # The following locals are used to define the firewall rules for the hub resources
  network_rule_collection = [
    {
      name     = "AllowAzureCloud"
      priority = "100"
      action   = "Allow"
      rules = [
        {
          name                  = "AzureCloud"
          protocols             = ["Any"]
          source_addresses      = ["*"]
          destination_addresses = ["AzureCloud"]
          destination_ports     = ["*"]
        }
      ]
    },
    { # Allow App Service Environment
      name     = "AppServiceEnvironment"
      priority = "300"
      action   = "Allow"
      rules = [
        {
          name                  = "NTP"
          protocols             = ["Any"]
          source_addresses      = ["*"]
          destination_addresses = ["*"]
          destination_ports     = ["123"]
        }
      ]
    },
    { # Allow App Service Environment
      name     = "AzureMonitor"
      priority = "500"
      action   = "Allow"
      rules = [
        {
          name                  = "AzureMonitor"
          protocols             = ["TCP"]
          source_addresses      = ["*"]
          destination_addresses = ["AzureMonitor"]
          destination_ports     = ["80", "443", "12000"]
        }
      ]
    },
    {
      name     = "AllowTrafficBetweenSpokes"
      priority = "200"
      action   = "Allow"
      rules = [
        {
          name                  = "AllSpokeTraffic"
          protocols             = ["Any"]
          source_addresses      = ["${var.firewall_supernet_IP_address}"]
          destination_addresses = ["*"]
          destination_ports     = ["*"]
        }
      ]
    }
  ]
  application_rule_collection = [
    {
      name     = "AzureAuth"
      priority = "110"
      action   = "Allow"
      rules = [
        {
          name              = "msftauth"
          source_addresses  = ["*"]
          destination_fqdns = ["aadcdn.msftauth.net", "aadcdn.msauth.net"]
          protocols = {
            type = "Https"
            port = 443
          }
        }
      ]
    },
    { # Allow App Service Environment
      name     = "AppServiceEnvironment"
      priority = "500"
      action   = "Allow"
      rules = [
        {
          name              = "AppServiceEnvironment"
          source_addresses  = ["*"]
          destination_fqdns = ["AppServiceEnvironment", "WindowsUpdate"]
          protocols = {
            type = "Https"
            port = 443
          }
        }
      ]
    }
  ]

  # The following locals are used to define the bastion host for the hub resources
  enable_bastion_host             = var.enable_bastion_host
  bastion_host_sku                = "Standard"
  bastion_subnet_address_prefixes = ["10.0.100.160/27"]
}

# The following locals are used to landing Zone - Partner Environment - Spokes
locals {
  # The following locals are used to define the spoke resources
  deployed_to_hub_subscription = true
  deny_all_inbound             = false

  # Peerings
  allow_virtual_spoke_network_access = var.allow_virtual_spoke_network_access
  allow_forwarded_spoke_traffic      = var.allow_forwarded_spoke_traffic
  allow_gateway_spoke_transit        = var.allow_gateway_spoke_transit
  use_remote_spoke_gateway           = var.use_remote_spoke_gateway

  # The following locals are used to define the ops resources
  ops_name                     = var.ops_name
  ops_vnet_address_space       = var.ops_vnet_address_space
  ops_subnet_addresses         = var.ops_vnet_subnet_address_prefixes
  ops_vnet_subnets             = {}
  ops_subnet_service_endpoints = var.ops_vnet_subnet_service_endpoints
  ops_nsg_rules = [
    {
      name                       = "Allow-Traffic-From-Spokes"
      priority                   = 200
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "*"
      source_port_range          = "*"
      destination_port_ranges    = ["22", "80", "443", "3389"]
      source_address_prefixes    = ["10.0.120.0/26"]
      destination_address_prefix = "10.0.115.0/26"
    },
  ]

  # The following locals are used to define the shared services resources
  svcs_name               = var.svcs_name
  svcs_vnet_address_space = var.svcs_vnet_address_space
  svcs_subnet_addresses   = var.svcs_vnet_subnet_address_prefixes
  svcs_vnet_subnets = {
    pe-snet = {
      name                                       = "pe"
      address_prefixes                           = var.svcs_pe_subnet_address_prefixes
      service_endpoints                          = var.svcs_vnet_subnet_service_endpoints
      private_endpoint_network_policies_enabled  = false
      private_endpoint_service_endpoints_enabled = true
    }
  }
  svcs_subnet_service_endpoints = var.svcs_vnet_subnet_service_endpoints
  svcs_nsg_rules = [
    {
      name                       = "Allow-Traffic-From-Spokes"
      priority                   = 200
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "*"
      source_port_range          = "*"
      destination_port_ranges    = ["22", "80", "443", "3389"]
      source_address_prefixes    = ["10.0.115.0/26"]
      destination_address_prefix = "10.0.120.0/26"
    },
  ]
}
