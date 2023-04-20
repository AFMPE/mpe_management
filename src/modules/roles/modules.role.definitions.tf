# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy Custom Role Definitions for Azure Policy in Partner Environments
DESCRIPTION: The following components will be options in this deployment
             * Custom Role Definitions
AUTHOR/S: jspinella
*/

#############################################
### Custom Role Definitions Configuations ###
#############################################
resource "azurerm_role_definition" "network_operations" {
  depends_on = [
    time_sleep.after_azurerm_management_group,
  ]
  name        = "Custom - Network Operations (NetOps)"
  scope       = data.azurerm_subscription.current.id
  description = "Platform-wide global connectivity management: virtual networks, UDRs, NSGs, NVAs, VPN, Azure ExpressRoute, and others."
  permissions {
    actions = [
      "Microsoft.Network/virtualNetworks/read",
      "Microsoft.Network/virtualNetworks/virtualNetworkPeerings/read",
      "Microsoft.Network/virtualNetworks/virtualNetworkPeerings/write",
      "Microsoft.Network/virtualNetworks/virtualNetworkPeerings/delete",
      "Microsoft.Network/virtualNetworks/peer/action",
      "Microsoft.Resources/deployments/operationStatuses/read",
      "Microsoft.Resources/deployments/write",
      "Microsoft.Resources/deployments/read"
    ]
    data_actions     = []
    not_actions      = []
    not_data_actions = []
  }
  assignable_scopes = ["${module.mod_management_group.0.management_groups["/providers/Microsoft.Management/managementGroups/platforms"].id}"]
}

resource "azurerm_role_definition" "platform_operations" {
  depends_on = [
    time_sleep.after_azurerm_management_group,
  ]
  name        = "Custom - Platform Operations (AppOps)"
  scope       = data.azurerm_subscription.current.id
  description = "Role granted for application/operations team at resource group level"
  permissions {
    actions = [
      "*"
    ]
    data_actions = []
    not_actions = [
      "Microsoft.Authorization/*/write",
      "Microsoft.Network/publicIPAddresses/write",
      "Microsoft.Network/virtualNetworks/write",
      "Microsoft.Network/virtualNetworks/*/write",
      "Microsoft.Network/virtualNetworks/*/delete",
      "Microsoft.Network/virtualNetworks/peer/action",
      "Microsoft.KeyVault/locations/deletedVaults/purge/action",
      "Microsoft.Resources/deployments/write",    
    ]
    not_data_actions = []
  }
  assignable_scopes = ["${module.mod_management_group.0.management_groups["/providers/Microsoft.Management/managementGroups/workloads"].id}"]
}

resource "time_sleep" "after_azurerm_role_definition" {
  depends_on = [
    time_sleep.after_azurerm_management_group,
    azurerm_role_definition.network_operations,
    azurerm_role_definition.platform_operations,
  ]

  triggers = {
    "azurerm_role_definition_noops" = jsonencode(keys(azurerm_role_definition.network_operations)),
    "azurerm_role_definition_noops" = jsonencode(keys(azurerm_role_definition.platform_operations))
  }

  create_duration  = local.create_duration_delay["after_azurerm_role_definition"]
  destroy_duration = local.destroy_duration_delay["after_azurerm_role_definition"]
}
