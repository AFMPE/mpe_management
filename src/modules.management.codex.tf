# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
SUMMARY: Module to deploy an Code X environment
DESCRIPTION: The following components will be options in this deployment
             * Code X Resource Group
AUTHOR/S: jspinella
*/

##############################
###  Code X Configuations  ###
##############################

module "mod_codex" {
  source = "./modules/codex"

  required                       = var.required
  location                       = var.default_location
  subscription_id_hub            = var.subscription_id_hub  
  state_sa_rg                    = local.state_sa_rg
  state_sa_name                  = local.state_sa_name
  state_sa_container_name        = local.state_sa_container_name
}