resource "my_alert_rule" "rule_184" {
  name = "Suspicious Service Principal creation activity"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Low
  query = <<EOF
let timeframe = 60m;
let lookback = 10m;
let account_created =
AuditLogs 
  | where ActivityDisplayName == "Add service principal"
  | where Result == "success"
  | extend AppID = tostring(AdditionalDetails[1].value)
  | extend creationTime = ActivityDateTime
  | extend userPrincipalName_creator = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend ipAddress_creator = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress);
let account_activity =
AADServicePrincipalSignInLogs
  | extend Activities = pack("ActivityTime", TimeGenerated ,"IpAddress", IPAddress, "ResourceDisplayName", ResourceDisplayName)
  | extend AppID = AppId
  | summarize make_list(Activities) by AppID;
let account_deleted =
AuditLogs 
  | where OperationName == "Remove service principal"
  | where Result == "success"
  | extend AppID = tostring(AdditionalDetails[1].value)
  | extend deletionTime = ActivityDateTime
  | extend userPrincipalName_deleter = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend ipAddress_deleter = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress);
let account_credentials =
AuditLogs
  | where OperationName contains "Update application - Certificates and secrets management"
  | where Result == "success"
  | extend AppID = tostring(AdditionalDetails[1].value)
  | extend credentialCreationTime = ActivityDateTime;
let roles_assigned =
AuditLogs
  | where ActivityDisplayName == "Add app role assignment to service principal"
  | extend AppID = tostring(TargetResources[1].displayName)
  | extend AssignedRole =  iff(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].displayName)=="AppRole.Value", tostring(parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].newValue))),"")
  | extend AssignedRoles = pack("Role", AssignedRole)
  |summarize  make_list(AssignedRoles) by AppID;
account_created 
  | join kind= inner (account_activity) on AppID, AppID 
  | join kind= inner (account_deleted) on AppID, AppID 
  | join kind= inner (account_credentials) on AppID, AppID 
  | join kind= inner (roles_assigned) on AppID, AppID
  | where deletionTime - creationTime < lookback
  | where tolong(deletionTime - creationTime) >= 0
  | where creationTime > ago(timeframe)
  | extend AliveTime = deletionTime - creationTime
  | project AADTenantId, AppID, creationTime, deletionTime, userPrincipalName_creator, userPrincipalName_deleter, ipAddress_creator, ipAddress_deleter, list_Activities , list_AssignedRoles, AliveTime
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = userPrincipalName_creator
    }
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = userPrincipalName_deleter
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = ipAddress_creator
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = ipAddress_deleter
    }
  }
  tactics = ['CredentialAccess', 'PrivilegeEscalation', 'InitialAccess']
  techniques = ['T1078', 'T1528']
  display_name = Suspicious Service Principal creation activity
  description = <<EOT
This alert will detect creation of an SPN, permissions granted, credentials cretaed, activity and deletion of the SPN in a time frame (default 10 minutes)
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = P1D
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = None
    group_by_custom_details = None
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
