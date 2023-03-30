# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*  
SUMMARY:  Module to deploy a Bastion Jumpbox
DESCRIPTION: This module deploys a Bastion Jumpbox to the Hub Network
AUTHOR/S: jspinella
*/

#####################################
## Bastion Jumpbox Configuration  ###
#####################################

#############################
### Naming Configuations  ###
#############################
data "azurenoopsutils_resource_name" "bastion_vm" {
  name          = local.hub_name
  resource_type = "azurerm_linux_virtual_machine"
  prefixes      = [local.org_name, module.mod_azure_region_lookup.location_short]
  suffixes      = [local.deploy_environment, "bas"]
  use_slug      = true
  clean_input   = true
  separator     = "-"
}

data "azurenoopsutils_resource_name" "bastion_nic" {
  name          = local.hub_name
  resource_type = "azurerm_network_interface"
  prefixes      = [local.org_name, module.mod_azure_region_lookup.location_short]
  suffixes      = [local.deploy_environment, "bas"]
  use_slug      = true
  clean_input   = true
  separator     = "-"
}

resource "azurerm_network_interface" "bastion_jumpbox_nic" {
  count               = local.enable_bastion_host ? 1 : 0
  name                = data.azurenoopsutils_resource_name.bastion_nic.result
  location            = module.mod_azure_region_lookup.location_cli
  resource_group_name = module.mod_hub_network.hub_resource_group_name

  ip_configuration {
    name                          = "bastion-jumpbox-ipconfig"
    subnet_id                     = module.mod_hub_network.hub_default_subnet_id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "bastion_jumpbox_vm" {
  count                           = local.enable_bastion_host ? 1 : 0
  name                            = data.azurenoopsutils_resource_name.bastion_vm.result
  resource_group_name             = module.mod_hub_network.hub_resource_group_name
  location                        = module.mod_azure_region_lookup.location_cli
  size                            = "Standard_F2"
  admin_username                  = "adminuser"
  disable_password_authentication = false
  admin_password                  = "P@ssw0rd1234"
  network_interface_ids = [
    azurerm_network_interface.bastion_jumpbox_nic.0.id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "16.04-LTS"
    version   = "latest"
  }
}