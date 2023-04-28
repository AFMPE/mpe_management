resource "my_alert_rule" "rule_199" {
  name = "RemoteManagementUsers Group Changed"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = High
  query = <<EOF
SecurityEvent
| sort by TimeGenerated
| where EventID == "4735"
| where TargetUserName == "Remote Management Users"
| project TimeGenerated,Account,Computer,TargetUserName,Activity,EventData
| extend AccountCustomEntity = Account 
| extend HostCustomEntity = Computer

EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = Account
    }
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = Computer
    }
  }
  tactics = ['PrivilegeEscalation']
  techniques = ['T1484']
  display_name = RemoteManagementUsers Group Changed
  description = <<EOT
'Detects when changes are made to the RemoteManagementUsers group in AD, this group allows users to login via WinRM and RDP'

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
