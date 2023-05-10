
/* module "mod_virtual_machine" {
  source  = "azurenoops/overlays-virtual-machine/azurerm"
  version = ">= 1.0.0"

  # Resource Group, location, VNet and Subnet details
  existing_resource_group_name = module.mod_codex_rg.resource_group_name
  location                     = var.location
  deploy_environment           = var.deploy_environment
  org_name                     = var.org_name
  workload_name                = var.workload_name

  # Lookup Network Information for VM deployment
  existing_virtual_network_resource_group_name = data.terraform_remote_state.landing_zone.outputs.hub_resource_group_name
  existing_virtual_network_name                = data.terraform_remote_state.landing_zone.outputs.hub_vnet_name
  existing_subnet_name                         = data.terraform_remote_state.landing_zone.outputs.hub_subnet_name
  existing_network_security_group_name         = azurerm_network_security_group.linux-nsg.name

  # This module supports a variety of pre-configured Linux and Windows distributions.
  # See the README.md file for more pre-defined Ubuntu, Centos, and RedHat images.
  # If you use gen2 distributions, please use gen2 images with supported VM sizes.
  # To generate a random admin password, specify 'disable_password_authentication = false' 
  # To use your own password, specify a valid password with the 'admin_password' parameter 
  # To produce an SSH key pair, specify 'generate_admin_ssh_key = true'
  # To use an existing key pair, set 'admin_ssh_key_data' to the path of a valid SSH public key.  
  os_type                 = "linux"
  linux_distribution_name = "ubuntu2004"
  virtual_machine_size    = "Standard_B2s"
  generate_admin_ssh_key  = true
  instances_count         = 2 # Number of VM's to be deployed

  # The proximity placement group, Availability Set, and assigning a public IP address to VMs are all optional.
  # If you don't wish to utilize these arguments, delete them from the module. 
  enable_proximity_placement_group   = true
  enable_vm_availability_set         = true
  private_ip_address_allocation_type = "Static" # Static or Dynamic
  private_ip_address                 = ["10.0.1.36", "10.0.1.37"]

  # Network Seurity group port definitions for each Virtual Machine 
  # NSG association for all network interfaces to be added automatically.
  # If 'existing_network_security_group_name' is supplied, the module will use the existing NSG.
  nsg_inbound_rules = [
    {
      name                   = "ssh"
      destination_port_range = "22"
      source_address_prefix  = "*"
    },
    {
      name                   = "http"
      destination_port_range = "80"
      source_address_prefix  = "*"
    },
  ]

  # Boot diagnostics are used to troubleshoot virtual machines by default. 
  # To use a custom storage account, supply a valid name for'storage_account_name'. 
  # Passing a 'null' value will use a Managed Storage Account to store Boot Diagnostics.
  enable_boot_diagnostics = true

  # Attach a managed data disk to a Windows/Linux virtual machine. 
  # Storage account types include: #'Standard_LRS', #'StandardSSD_ZRS', #'Premium_LRS', #'Premium_ZRS', #'StandardSSD_LRS', #'UltraSSD_LRS' (UltraSSD_LRS is only accessible in regions that support availability zones).
  # Create a new data drive - connect to the VM and execute diskmanagemnet or fdisk.
  data_disks = [
    {
      name                 = "disk1"
      disk_size_gb         = 100
      storage_account_type = "StandardSSD_LRS"
    },
    {
      name                 = "disk2"
      disk_size_gb         = 200
      storage_account_type = "Standard_LRS"
    }
  ]

  # AAD Login is used to login to the VM using Azure Active Directory credentials.
  /* aad_login_enabled = true
  aad_login_user_objects_ids = [
    data.azuread_group.vm_users_group.object_id
  ]

  aad_login_admin_objects_ids = [
    data.azuread_group.vm_admins_group.object_id
  ] */

  # (Optional) To activate Azure Monitoring and install log analytics agents 
  # (Optional) To save monitoring logs to storage, specify'storage_account_name'.    
  #log_analytics_workspace_id = azurerm_log_analytics_workspace.linux-log.id

  # Deploy log analytics agents on a virtual machine. 
  # Customer id and primary shared key for Log Analytics workspace are required.
  #deploy_log_analytics_agent                 = true
  #log_analytics_customer_id                  = azurerm_log_analytics_workspace.linux-log.workspace_id
  #log_analytics_workspace_primary_shared_key = azurerm_log_analytics_workspace.linux-log.primary_shared_key

  # Adding additional TAG's to your Azure resources
  #add_tags = {
   # Exmaple = "basic_linux_virtual_machine_using_existing_RG"
  #}
#} */