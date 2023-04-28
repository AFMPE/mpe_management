resource "my_alert_rule" "rule_253" {
  name = "Possible LSASS memory access via lsadump or similar tool (via audit)"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
SecurityEvent | where (EventID == 4656 and (ObjectType == "SAM_DOMAIN") and (ProcessName == "lsass.exe") and (AccessMask == "0x705")) | extend AccountCustomEntity = Account | extend HostCustomEntity = Computer

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
  tactics = ['CredentialAccess']
  techniques = ['T1003']
  display_name = Possible LSASS memory access via lsadump or similar tool (via audit)
  description = <<EOT
'Detects attempts to access LSASS process via mimikatz lsadump.'

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
