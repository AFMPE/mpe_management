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
}