resource "my_alert_rule" "rule_260" {
  name = "Potential Remote Desktop Tunneling"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
SecurityEvent
   | where EventID in (4624,4625) and LogonType in (10) and IpAddress in ("::1","127.0.0.1")
   | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by EventID, Computer, TargetUserName, TargetLogonId, LogonType, IpAddress
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = TargetUserName
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = Computer
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IpAddress
    }
  }
  tactics = ['CommandAndControl']
  techniques = ['T1572']
  display_name = Potential Remote Desktop Tunneling
  description = <<EOT
This query detects remote desktop authentication attempts with a localhost source address which can indicate a tunneled login.
Ref: https://www.mandiant.com/resources/bypassing-network-restrictions-through-rdp-tunneling
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
