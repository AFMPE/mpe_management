resource "my_alert_rule" "rule_345" {
  name = "Secret Server - Repeated Login Failures"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT10M
  query_period = PT10M
  severity = Medium
  query = <<EOF
CommonSecurityLog
| where DeviceVendor == "Thycotic Software"
| where DeviceProduct == "Secret Server"
| where DestinationUserName !has "conquestcyber.com"
| where DestinationUserName <> ""
| where not(SourceUserName has "conquest_api" and DestinationUserName has"conquest_api")
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), FailedLogonCount = count() by Activity, SourceUserName, SourceIP, DestinationUserID, DestinationUserName 
| where FailedLogonCount >= 3 // failed logins required to trigger the alert
| extend timestamp = StartTime
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
  display_name = Secret Server - Repeated Login Failures
  description = <<EOT
This rule detects when there are repeated failed attempts to login to non-conquest users on Secret Server. This would indecate a brute force of a local account on secret server. 
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
