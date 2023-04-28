resource "my_alert_rule" "rule_280" {
  name = "Workspace deletion attempt from an infected device"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
SecurityAlert 
| where AlertName == "Sign-in from an infected device"
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
| summarize count() by AlertName, AlertSeverity, CompromisedEntity, Account, IpAddress
| join kind=inner 
(
AzureActivity
| where OperationNameValue hassuffix ("/workspaces/computes/delete")
| where ActivityStatusValue =~ "Succeeded"
| summarize  StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ActivityTimeStamp = makelist(TimeGenerated), ActivityStatusValue = makelist(ActivityStatusValue),  OperationIds = makelist(OperationId), CorrelationIds = makelist(CorrelationId), Resources = makelist(Resource), ResourceGroups = makelist(ResourceGroup), ResourceIds = makelist(ResourceId), ActivityCountByCallerIPAddress = count()  
by CallerIpAddress, Caller, OperationNameValue
) on $left. IpAddress == $right. CallerIpAddress
| extend timestamp = StartTimeUtc, AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress
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
  tactics = ['InitialAccess', 'Impact']
  techniques = ['T1078', 'T1489']
  display_name = Workspace deletion attempt from an infected device
  description = <<EOT
This hunting query will alert on any sign-ins from devices infected with malware in correlation with potential workspace deletion activity. 
Attackers may attempt to delete  workspaces containing  compute instances  after successful compromise to cause service unavailability to regular business operation.
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
