resource "my_alert_rule" "rule_379" {
  name = "Fake computer account created"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
SecurityEvent
| where EventID == 4720 and TargetUserName endswith "$"
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by Computer, SubjectUserName, SubjectUserSid, SubjectLogonId, TargetUserName, TargetSid
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = SubjectUserName
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = Computer
    }
  }
  tactics = ['DefenseEvasion']
  techniques = ['T1564']
  display_name = Fake computer account created
  description = <<EOT
This query detects domain user accounts creation (event ID 4720) where the username ends with $. 
Accounts that end with $ are normally domain computer accounts and when they are created the event ID 4741 is generated instead.
Ref: https://blog.menasec.net/2019/02/threat-hunting-6-hiding-in-plain-sights.html
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
