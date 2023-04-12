# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy an SCCA Compliant Mission Partner Environment
DESCRIPTION: The following components will be options in this deployment
            * Mission Enclave - Management Groups and Subscriptions
              * Management Group
                * Org
                * Team
              * Subscription
                * Hub
                * Operations
                * Shared Services
                * Partner
                 * Global SA
AUTHOR/S: jspinella
*/

terraform {
  # It is recommended to use remote state instead of local
  backend "azurerm" {
    resource_group_name  = "afmpe-network-artifacts-rg"
    storage_account_name = "afmpetfmgtprodh8dc4qua"
    container_name       = "core-mgt-prod-tfstate"
    key                  = "prod.terraform.tfstate"
  }
  
  required_version = ">= 1.3"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.36"
    }      
    null = {
      source = "hashicorp/null"
    }
    random = {
      version = "= 3.4.3"
      source  = "hashicorp/random"
    }
    time = {
      source  = "hashicorp/time"
      version = "0.8.0"
    }
  }
}

provider "azurerm" {  
  features {}
}
