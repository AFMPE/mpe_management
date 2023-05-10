
module "mod_key_vault" {  
  source                       = "azurenoops/overlays-key-vault/azurerm"
  version                      = ">= 1.0.0"
  existing_resource_group_name = module.mod_codex_rg.resource_group_name
  location                     = local.location
  environment                  = local.environment
  deploy_environment           = local.deploy_environment
  org_name                     = local.org_name
  workload_name                = local.workload_name

  # This is to enable the features of the key vault
  enabled_for_deployment          = false
  enabled_for_disk_encryption     = false
  enabled_for_template_deployment = false

  # This is to enable public access to the key vault, since we are using a private endpoint, we will disable it
  public_network_access_enabled = false

  # Once `Purge Protection` has been Enabled it's not possible to Disable it
  # Deleting the Key Vault with `Purge Protection` enabled will schedule the Key Vault to be deleted
  # The default retention period is 90 days, possible values are from 7 to 90 days
  # use `soft_delete_retention_days` to set the retention period
  enable_purge_protection = false
  
  # Creating Private Endpoint requires, VNet name to create a Private Endpoint
  # By default this will create a `privatelink.vaultcore.azure.net` DNS zone. if created in commercial cloud
  # To use existing subnet, specify `existing_subnet_id` with valid subnet id. 
  # To use existing private DNS zone specify `existing_private_dns_zone` with valid zone name
  # Private endpoints doesn't work If not using `existing_subnet_id` to create redis inside a specified VNet.
  enable_private_endpoint       = false

  # Current user should be here to be able to create keys and secrets
  #admin_objects_ids = [
  #  data.azuread_group.admin_group.id
  #]

  # This is to enable resource locks for the key vault. 
  enable_resource_locks = local.enable_resource_locks

  # Tags for Azure Resources
  add_tags = merge(local.hub_resources_tags, )
}