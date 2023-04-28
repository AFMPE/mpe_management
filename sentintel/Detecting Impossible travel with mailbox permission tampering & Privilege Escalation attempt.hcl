resource "my_alert_rule" "rule_54" {
  name = "Detecting Impossible travel with mailbox permission tampering & Privilege Escalation attempt"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
SecurityAlert 
| where AlertName == "Impossible travel activity"
| extend Extprop = parsejson(Entities)
| mv-expand Extprop
| extend Extprop = parsejson(Extprop)
| extend CmdLine = iff(Extprop['Type']=="process", Extprop['CommandLine'], '')
| extend File = iff(Extprop['Type']=="file", Extprop['Name'], '')
| extend Account = Extprop['Name']
| extend Domain = Extprop['UPNSuffix']
| extend Account = iif(isnotempty(Domain) and Extprop['Type']=="account", tolower(strcat(Account, "@", Domain)), iif(Extprop['Type']=="account", tolower(Account), ""))
| extend IpAddress = iff(Extprop["Type"] == "ip",Extprop['Address'], '')
| extend Process = iff(isnotempty(CmdLine), CmdLine, File)
| project TimeGenerated,Account,IpAddress,CompromisedEntity,Description,ProviderName,ResourceId
| join kind=inner
(
OfficeActivity
| where Operation =~ "Add-MailboxPermission"
| extend value = tostring(parse_json(Parameters)[3].Value)
| where value contains "FullAccess"
| where ResultStatus == "True"
| project Parameters,TimeGenerated,value,RecordType,Operation,OrganizationId,UserType,UserKey,OfficeWorkload,ResultStatus,OfficeObjectId,UserId,ClientIP,ExternalAccess,OriginatingServer,OrganizationName,TenantId,ElevationTime,SourceSystem,OfficeId,OfficeTenantId,Type,SourceRecordId
) on $left.Account == $right.UserId
| join kind=inner
(
AuditLogs
| where ActivityDisplayName =~ "Add eligible member to role in PIM requested (timebound)"
| where AADOperationType =~ "CreateRequestEligibleRole"
| where TargetResources has_any ("-PRIV", "Administrator", "Security")
| extend BuiltinRole = tostring(parse_json(TargetResources[0].displayName))
| extend CustomGroup = tostring(parse_json(TargetResources[3].displayName))
| extend TargetAccount = tostring(parse_json(TargetResources[2].displayName))
| extend Initiatedby = Identity
| project TimeGenerated, ActivityDisplayName, AADOperationType, Initiatedby, TargetAccount, BuiltinRole, CustomGroup, LoggedByService, Result, ResourceId, Id
| sort by TimeGenerated desc
) on $left.UserId == $right.Initiatedby
| project AADOperationType, ActivityDisplayName,AccountCustomEntity=Initiatedby, Id,ResourceId,IPCustomEntity=IpAddress
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['InitialAccess', 'PrivilegeEscalation']
  techniques = ['T1078', 'T1548']
  display_name = Detecting Impossible travel with mailbox permission tampering & Privilege Escalation attempt
  description = <<EOT
This hunting query will alert on any Impossible travel activity in correlation with mailbox permission tampering followed by account being added to a PIM managed privileged group.
Ensure this impossible travel incident with increase of privileges is legitimate in your environment.
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
