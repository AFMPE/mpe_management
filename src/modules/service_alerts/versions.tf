# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy an Mission Partner Environment Service Alerts
DESCRIPTION: The following components will be options in this deployment
              * Service Alerts
AUTHOR/S: jspinella
*/

# Configure the minimum required providers supported by this module
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.19.0"
    }
  }
  required_version = ">= 1.3.1"
}