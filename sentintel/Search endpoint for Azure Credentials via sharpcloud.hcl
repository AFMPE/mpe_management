resource "my_alert_rule" "rule_118" {
  name = "Search endpoint for Azure Credentials via sharpcloud"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = High
  query = <<EOF
let SE =(SecurityEvent
| where AccountType == "User"
| where NewProcessName has "SharpCloud.exe"
| where CommandLine has_any ("all", "aws", "gcloud", "azure")
| extend AccountCustomEntity = Account, HostCustomEntity = Computer);
let DPE = (DeviceProcessEvents
| where InitiatingProcessFileName has "SharpCloud.exe"
| where ProcessCommandLine has_any ("all", "aws", "glcloud", "azure")
| extend AccountCustomEntity = AccountUpn, HostCustomEntity = DeviceName);
SE
| union DPE
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
  }
  tactics = ['LateralMovement']
  techniques = ['T1021']
  display_name = Search endpoint for Azure Credentials via sharpcloud
  description = <<EOT
'Detects when SharpCloud is run to gather cloud credentials on a machine.'

EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5M
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
