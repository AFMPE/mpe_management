# hub_network module outputs
output "hub_resource_group_name" {
  description = "The name of the hub resource group"
  value       = module.landing_zone.hub_resource_group_name
}

output "hub_virtual_network_name" {
  description = "The name of the hub virtual network"
  value       = module.landing_zone.hub_virtual_network_name
}

output "hub_virtual_network_id" {
  description = "The id of the hub virtual network"
  value       = module.landing_zone.hub_virtual_network_id
}

output "hub_default_subnet_id" {
  description = "The id of the default subnet"
  value       = module.landing_zone.hub_default_subnet_id
}

output "hub_default_subnet_name" {
  description = "The name of the default subnet"
  value       = module.landing_zone.hub_default_subnet_name
}

# ops_network module outputs
output "operations_resource_group_name" {
  description = "The name of the operations resource group"
  value       = module.landing_zone.operations_resource_group_name
}

output "operations_virtual_network_name" {
  description = "The name of the spoke virtual network"
  value       = module.landing_zone.operations_virtual_network_name
}

output "operations_default_subnet_id" {
  description = "The id of the default subnet"
  value       = module.landing_zone.operations_default_subnet_id
}

output "operations_default_subnet_name" {
  description = "The id of the default subnet"
  value       = module.landing_zone.operations_default_subnet_name
}

# svcs_network module outputs
output "svcs_resource_group_name" {
  description = "The name of the shared services resource group"
  value       = module.landing_zone.svcs_resource_group_name
}

output "svcs_virtual_network_name" {
  description = "The name of the spoke virtual network"
  value       = module.landing_zone.svcs_virtual_network_name
}

output "svcs_default_subnet_id" {
  description = "The id of the default subnet"
  value       = module.landing_zone.svcs_default_subnet_id
}

output "svcs_default_subnet_name" {
  description = "The id of the default subnet"
  value       = module.landing_zone.svcs_default_subnet_name
}
