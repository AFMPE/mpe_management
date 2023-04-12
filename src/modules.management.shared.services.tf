# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy an Azure Partner Environment
DESCRIPTION: The following components will be options in this deployment
             * Management Group Hierarchy
             * Custom Role Definitions
             * Hub/Spoke Network Architecture
AUTHOR/S: jspinella
*/

################################
### Hub/Spoke Configuations  ###
################################

module "shared_services" {
  source = "./modules/shared_services"

  # Global Configuration
  required                       = var.required
  location                       = var.default_location
  subscription_id_hub            = var.subscription_id_hub
  subscription_id_operations     = coalesce(var.subscription_id_operations, var.subscription_id_hub)
  subscription_id_identity       = coalesce(var.subscription_id_identity, var.subscription_id_hub)
  subscription_id_sharedservices = coalesce(var.subscription_id_sharedservices, var.subscription_id_hub)


}
