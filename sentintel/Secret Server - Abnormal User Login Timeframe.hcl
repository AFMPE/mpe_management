resource "my_alert_rule" "rule_65" {
  name = "Secret Server - Abnormal User Login Timeframe"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT15M
  query_period = PT15M
  severity = Medium
  query = <<EOF
CommonSecurityLog
| where DeviceVendor == "Thycotic Software"
| where DeviceProduct == "Secret Server"
| where Activity has "USER - LOGIN"
| extend hour = datetime_part("hour", TimeGenerated), day = dayofweek(TimeGenerated)
//Alert on logins 7pm-7AM CST but ignore the weekly maintenance window on Tuesday Night of 7pm CST - 12AM CST)
| where ((hour > 01 and day != "3.00:00:00") and (hour < 13 and day != "3.00:00:00")) or ((hour > 05 and day == "3.00:00:00") and (hour < 13 and day == "3.00:00:00"))
| where not (SourceUserName has "conquest_api")
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = SourceUserName
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = SourceIP
    }
  }
  tactics = ['CredentialAccess']
  techniques = ['T1110']
  display_name = Secret Server - Abnormal User Login Timeframe
  description = <<EOT
This rule alerts when a user logs in outside of normal business hours, 7am-7pm. 
EOT
  enabled = False
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
