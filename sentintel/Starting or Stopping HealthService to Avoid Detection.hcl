resource "my_alert_rule" "rule_240" {
  name = "Starting or Stopping HealthService to Avoid Detection"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
SecurityEvent
| where EventID == 4656
| extend EventData = parse_xml(EventData).EventData.Data
| mv-expand bagexpansion=array EventData
| evaluate bag_unpack(EventData)
| extend Key = tostring(column_ifexists('@Name', "")), Value = column_ifexists('#text', "")
| evaluate pivot(Key, any(Value), TimeGenerated, TargetAccount, Computer, EventSourceName, Channel, Task, Level, EventID, Activity, TargetLogonId, SourceComputerId, EventOriginId, Type, _ResourceId, TenantId, SourceSystem, ManagementGroupName, IpAddress, Account)
| extend ObjectServer = column_ifexists('ObjectServer', ""), ObjectType = column_ifexists('ObjectType', ""), ObjectName = column_ifexists('ObjectName', "")
| where isnotempty(ObjectServer) and isnotempty(ObjectType) and isnotempty(ObjectName)
| where ObjectServer =~ "SC Manager" and ObjectType =~ "SERVICE OBJECT" and ObjectName =~ "HealthService"
// Comment out the join below if the SACL only audits users that are part of the Network logon users, i.e. with user/group target pointing to "NU."
| join kind=leftouter (
  SecurityEvent
  | where EventID == 4624
) on TargetLogonId
| project TimeGenerated, Computer, Account, TargetAccount, IpAddress,TargetLogonId, ObjectServer, ObjectType, ObjectName
| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account, IPCustomEntity = IpAddress
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['DefenseEvasion']
  techniques = ['T1562']
  display_name = Starting or Stopping HealthService to Avoid Detection
  description = <<EOT
This query detects events where an actor is stopping or starting HealthService to disable telemetry collection/detection from the agent.
 The query requires a SACL to audit for access request to the service.
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = P1D
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
