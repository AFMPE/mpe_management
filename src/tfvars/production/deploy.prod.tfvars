required = {
  org_name           = "ampe"
  deploy_environment = "prod"
  environment        = "public"
  metadata_host      = "management.azure.com"
}

default_location      = "eastus"

# Resource Locks
enable_resource_locks = false

contact_emails = ["mpe@afmpe.com"] # email addresses to send alerts to for this subscription
