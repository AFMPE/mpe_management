# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This is a sample configuration file for the MPE Landing Zone
# This file is used to configure the MPE Landing Zone.  
# It is used to set the default values for the variables used in the MPE Landing Zone.  The values in this file can be overridden by setting the same variable in the terraform.tfvars file.

#####################################
# Management Groups Configuration  ##
#####################################

enable_management_groups           = false   # enable management groups for this subscription
root_management_group_id           = "ampe" # the root management group id for this subscription
root_management_group_display_name = "ampe" # the root management group display name for this subscription

# Budgets for management groups
enable_management_groups_budgets = false
budget_contact_emails = ["ampe@missionpartners.us"] # email addresses to send alerts to for this subscription

###########################
## Global Configuration  ##
###########################

required = {
  org_name           = "ampe"                 # This Prefix will be used on most deployed resources.  10 Characters max.
  deploy_environment = "test"                 # dev | test | prod
  environment        = "public"               # public | usgovernment
  metadata_host      = "management.azure.com" # management.azure.com | management.usgovcloudapi.net
}

# The default region to deploy to
default_location = "eastus"

# Enable locks on resources
enable_resource_locks = false

# Used during testing, comment when not testing
subscription_id_hub = "930a247f-b4fa-4f1b-ad73-6a03cf1d0f4e"

####################################
## Security Center Configuration  ##
####################################

contact_emails = ["mpe@missionpartners.us"] # email addresses to send alerts to for this subscription

#########################################
## Remote Storage State Configuration  ##
#########################################

# Deployment state storage information
state_sa_name           = "afmpetfmgth8dc4qua"
state_sa_rg             = "afmpe-network-artifacts-rg"
state_sa_container_name = "core-mgt-tfstate"

################################
# Landing Zone Configuration  ##
################################

#########################
# Hub Virtual Network ###
#########################

hub_name                         = "hub-core"
hub_vnet_address_space           = ["10.0.100.0/24"]
hub_vnet_subnet_address_prefixes = ["10.0.100.128/27"]
hub_vnet_subnet_service_endpoints = [
  "Microsoft.KeyVault",
  "Microsoft.Sql",
  "Microsoft.Storage",
]

enable_firewall              = true
enable_force_tunneling       = true
firewall_supernet_IP_address = "10.0.96.0/19"
enable_bastion_host          = true

######################################
# Operations Spoke Virtual Network ###
######################################

ops_name                         = "ops-core"
ops_vnet_address_space           = ["10.0.115.0/24"]
ops_vnet_subnet_address_prefixes = ["10.0.115.0/27"]
ops_vnet_subnet_service_endpoints = [
  "Microsoft.KeyVault",
  "Microsoft.Sql",
  "Microsoft.Storage",
]

#########################
# OperationL Logging  ###
#########################

ops_logging_name                     = "ops-logging-core"
enable_sentinel                      = true
log_analytics_workspace_sku          = "PerGB2018"
log_analytics_logs_retention_in_days = 30

###########################################
# Shared Services Spoke Virtual Network ###
###########################################

svcs_name                         = "svcs-core"
svcs_vnet_address_space           = ["10.0.120.0/24"]
svcs_vnet_subnet_address_prefixes = ["10.0.120.0/27"]
svcs_pe_subnet_address_prefixes   = ["10.0.120.32/27"]
svcs_vnet_subnet_service_endpoints = [
  "Microsoft.KeyVault",
  "Microsoft.Sql",
  "Microsoft.Storage",
]

###################################
# Shared Services Configuration  ##
###################################

# Azure Key Vault
enabled_for_deployment = true
enabled_for_disk_encryption = true
enabled_for_template_deployment = true

admin_group_name = "afmpe_admins"

# Bastion VM

############################
# Sentinel Configuration  ##
############################

/* sentinel_rule_alerts = {
  "malicious_web_request" = {
    name                 = "A potentially malicious web request was executed against a web server"
    display_name         = "A potentially malicious web request was executed against a web server"
    description          = <<EOT
        Detects unobstructed Web Application Firewall (WAF) activity in sessions where the WAF blocked incoming requests by computing the 
        ratio between blocked requests and unobstructed WAF requests in these sessions (BlockvsSuccessRatio metric). A high ratio value for 
        a given client IP and hostname calls for further investigation of the WAF data in that session, due to the significantly high number 
        of blocked requests and a few unobstructed logs which may be malicious but have passed undetected through the WAF. The successCode 
        variable defines what the detection thinks is a successful status code, and should be altered to fit the environment.
        EOT
    enabled              = false
    severity             = "Medium"
    query                = <<EOF
        let queryperiod = 1d;
        let mode = 'Blocked';
        let successCode = dynamic(['200', '101','204', '400','504','304','401','500']);
        let sessionBin = 30m;
        AzureDiagnostics
        | where TimeGenerated > ago(queryperiod)
        | where Category == 'ApplicationGatewayFirewallLog' and action_s == mode
        | sort by hostname_s asc, clientIp_s asc, TimeGenerated asc
        | extend SessionBlockedStarted = row_window_session(TimeGenerated, queryperiod, 10m, ((clientIp_s != prev(clientIp_s)) or (hostname_s != prev(hostname_s))))
        | summarize SessionBlockedEnded = max(TimeGenerated), SessionBlockedCount = count() by hostname_s, clientIp_s, SessionBlockedStarted
        | extend TimeKey = range(bin(SessionBlockedStarted, sessionBin), bin(SessionBlockedEnded, sessionBin), sessionBin)
        | mv-expand TimeKey to typeof(datetime)
        | join kind = inner(
            AzureDiagnostics
            | where TimeGenerated > ago(queryperiod)
            | where Category == 'ApplicationGatewayAccessLog' and (isempty(httpStatus_d) or httpStatus_d in (successCode))
            | extend TimeKey = bin(TimeGenerated, sessionBin)
        ) on TimeKey, $left.hostname_s == $right.host_s, $left.clientIp_s == $right.clientIP_s
        | where TimeGenerated between (SessionBlockedStarted..SessionBlockedEnded)
        | extend
            originalRequestUriWithArgs_s = column_ifexists("originalRequestUriWithArgs_s", ""),
            serverStatus_s = column_ifexists("serverStatus_s", "")
        | summarize
            SuccessfulAccessCount = count(),
            UserAgents = make_set(userAgent_s, 250),
            RequestURIs = make_set(requestUri_s, 250),
            OriginalRequestURIs = make_set(originalRequestUriWithArgs_s, 250),
            SuccessCodes = make_set(httpStatus_d, 250),
            SuccessCodes_BackendServer = make_set(serverStatus_s, 250),
            take_any(SessionBlockedEnded, SessionBlockedCount)
            by hostname_s, clientIp_s, SessionBlockedStarted
        | where SessionBlockedCount > SuccessfulAccessCount
        | extend timestamp = SessionBlockedStarted, IPCustomEntity = clientIp_s
        | extend BlockvsSuccessRatio = SessionBlockedCount/toreal(SuccessfulAccessCount)
        | sort by BlockvsSuccessRatio desc, timestamp asc
        | project-reorder SessionBlockedStarted, SessionBlockedEnded, hostname_s, clientIp_s, SessionBlockedCount, SuccessfulAccessCount, BlockvsSuccessRatio, SuccessCodes, RequestURIs, OriginalRequestURIs, UserAgents
        EOF
    query_frequency      = "P1D"
    query_period         = "P1D"
    action               = "Log"
    suppression_duration = "PT5H"
    suppression_enabled  = false
    grouping             = false
    create_incident      = true
    incident_configuration = {
      reopen_closed_incident  = false
      lookback_duration       = "P1D"
      entity_matching_method  = "AllEntities"
      group_by_entities       = []
      group_by_alert_details  = ["None"]
      group_by_custom_details = ["None"]
    }
    entity_mappings = [
      {
        entity_type = "IP"
        field_mappings = [
          {
            identifier = "IPAddress"
            field_name = "IPCustomEntity"
          }
        ]
      }
    ]
    tactics    = ["InitialAccess"]
    techniques = ["T1190"]
    trigger_operator = ""
    trigger_threshold = 0
  }
}
 */