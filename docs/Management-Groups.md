# Create the Management Groups

The following will be created:

* Management Groups
* Management Group Subscriptions

Review and if needed, comment out and modify the variables within the "Management Groups" section of the common variable definitons file [parameters.prod.tfvars](./parameters.prod.tfvars). Do not modify if you plan to use the default values.

Sample:

```bash

##################################################
## Management Groups
##################################################
    # hub_vnet_addr_prefix           = "10.0.0.0/16"
    # azurefw_addr_prefix            = "10.0.1.0/24"
    # azurebastion_addr_prefix       = "10.0.0.0/24"

```

Navigate to the "/Management Groups" directory. 

```bash
cd management_groups
```
Deploy using Terraform Init, Plan and Apply

```bash

# Ensure the following state management runtime variables have been defined:
#   STORAGEACCOUNTNAME = 'xxxxx'
#   CONTAINERNAME      = 'xxxxx'
#   TFSTATE_RG         = 'xxxxx'



terraform init -backend-config="resource_group_name=$TFSTATE_RG" -backend-config="storage_account_name=$STORAGEACCOUNTNAME" -backend-config="container_name=$CONTAINERNAME"
```

```bash
terraform plan -out ampe.plan --var-file ../parameters.test.tfvars
```

```bash
terraform apply ampe.plan
```