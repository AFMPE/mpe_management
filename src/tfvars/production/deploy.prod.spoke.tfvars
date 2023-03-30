# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License. 

# 
required = {
  org_name           = "ampe"
  deploy_environment = "prod" # dev | test | prod
  environment        = "public" # public | usgovernement
  metadata_host      = "management.azure.com" # management.azure.com | management.usgovcloudapi.net | management.chinacloudapi.cn | management.microsoftazure.de
}

location = "eastus" # 

# Resource Locks
enable_resource_locks = false

#################
# Workload    ###
#################

wl_vnet_address_space           = ["10.0.125.0/24"]
wl_vnet_subnet_address_prefixes = ["10.0.125.0/27"]
wl_vnet_subnet_service_endpoints = [
  "Microsoft.KeyVault",
  "Microsoft.Sql",
  "Microsoft.Storage",
]
