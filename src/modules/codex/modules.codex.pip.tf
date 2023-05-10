# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#---------------------------------------------------------
# CodeX Public IP Creation
#----------------------------------------------------------
resource "azurerm_public_ip" "firewall_client_pip" {
  name                = ""
  resource_group_name = module.mod_codex_rg.resource_group_name
  location            = local.location
  allocation_method   = "Static"
  sku                 = "Standard"
  add_tags            = merge(local.hub_resources_tags, )
}
