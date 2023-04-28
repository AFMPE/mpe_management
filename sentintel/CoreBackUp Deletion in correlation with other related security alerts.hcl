resource "my_alert_rule" "rule_207" {
  name = "CoreBackUp Deletion in correlation with other related security alerts"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
SecurityAlert
| extend Extprop = parse_json(ExtendedProperties)
| extend Computer = iff(isnotempty(toupper(tostring(Extprop["Compromised Host"]))), toupper(tostring(Extprop["Compromised Host"])), tostring(parse_json(Entities)[0].HostName))
| extend Account = iff(isnotempty(tolower(tostring(Extprop["User Name"]))), tolower(tostring(Extprop["User Name"])), tolower(tostring(Extprop["user name"])))
| extend IpAddress = tostring(parse_json(ExtendedProperties).["IpAddress"]) 
| project TimeGenerated, AlertName, Computer, Account, IpAddress, ExtendedProperties
| extend timestamp = TimeGenerated, Account, MachineName = Computer, IpAddress
| join kind=inner
(
CoreAzureBackup
| where State =~ "Deleted"
| where OperationName =~ "BackupItem"
| extend data = split(BackupItemUniqueId, ";")
| extend AzureLocation = data[0], VaultId=data[1], MachineName=data[2], DrivesBackedUp=data[3]
| project timestamp = TimeGenerated, AzureLocation, VaultId, tostring(MachineName), DrivesBackedUp, State, BackupItemUniqueId, _ResourceId, OperationName, BackupItemFriendlyName
)
on MachineName
| project timestamp, AlertName, HostCustomEntity = MachineName, AccountCustomEntity = Account, ResourceCustomEntity = _ResourceId, IPCustomEntity = IpAddress, VaultId, AzureLocation, DrivesBackedUp, State, BackupItemUniqueId, OperationName, BackupItemFriendlyName
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = AzureResource
    field_mappings {
      identifier = ResourceId
      column_name = ResourceCustomEntity
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
  tactics = ['Impact']
  techniques = ['T1496']
  display_name = CoreBackUp Deletion in correlation with other related security alerts
  description = <<EOT
This query will help detect attackers attempt to delete backup containers in correlation with other alerts that could have triggered to help possibly reveal more details of attacker activity. 
Though such an activity could be legitimate as part of business operation, some ransomware actors may perform such operation to cause interruption to regular business services.
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
