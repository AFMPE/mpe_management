resource "my_alert_rule" "rule_91" {
  name = "User Account Creation"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Low
  query = <<EOF
SecurityEvent 
| where EventID == 4688 and (Process == "net.exe" or Process == "net1.exe") and not(ParentProcessName == "net.exe") and (CommandLine contains "user" and CommandLine contains "/add" or CommandLine contains "/ad")
| extend AccountCustomEntity = Account 
| extend HostCustomEntity = Computer

EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = AccountCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = HostCustomEntity
    }
  }
  tactics = ['Persistence']
  techniques = ['T1098']
  display_name = User Account Creation
  description = <<EOT
'Identifies attempts to create new local users. This is sometimes done by attackers to increase access to a system or domain.'

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
