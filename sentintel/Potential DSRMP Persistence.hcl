resource "my_alert_rule" "rule_224" {
  name = "Potential DSRMP Persistence"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Low
  query = <<EOF
SecurityEvent
| where EventID == "4657" 
or EventID == "4656" 
or EventID == "4678"
| where ObjectName contains "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Lsa\\DSRMADMINLOGONBEHAVIOR"
| extend AccountCustomEntity = Account 
| extend HostCustomEntity = Computer

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
  tactics = ['Persistence']
  techniques = ['T1053']
  display_name = Potential DSRMP Persistence
  description = <<EOT
'DSRM Persistence https://adsecurity.org/?p=1785'

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
