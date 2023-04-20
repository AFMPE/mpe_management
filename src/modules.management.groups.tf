# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy an Azure Partner Environment
DESCRIPTION: The following components will be options in this deployment
             * Management Group Hierarchy
AUTHOR/S: jspinella
*/

########################################
###  Management Group Configuations  ###
########################################

module "management_groups" {
  source = "./modules/management_groups"
  count  = var.enable_management_groups ? 1 : 0 # used in testing

  # Global Configuration
  root_management_group_id           = var.root_management_group_id
  root_management_group_display_name = var.root_management_group_display_name
  subscription_id_hub                = var.subscription_id_hub
  subscription_id_identity           = coalesce(var.subscription_id_identity, var.subscription_id_hub)
  subscription_id_operations         = coalesce(var.subscription_id_operations, var.subscription_id_hub)
  subscription_id_sharedservices     = coalesce(var.subscription_id_sharedservices, var.subscription_id_hub)
  subscription_id_internal           = var.subscription_id_internal
  subscription_id_sandbox            = var.subscription_id_sandbox
  subscription_id_partners_gsa_dev   = var.subscription_id_partners_gsa_dev
  subscription_id_partners_gsa_prod  = var.subscription_id_partners_gsa_prod
  contact_emails                     = var.contact_emails
}

