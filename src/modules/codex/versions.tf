# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy an Codex environment
DESCRIPTION: The following components will be options in this deployment
            * CodeX Resource Group
AUTHOR/S: jspinella
*/

provider "azurerm" {
  subscription_id = var.subscription_id_hub
  features {}
}
