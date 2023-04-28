resource "my_alert_rule" "rule_339" {
  name = "SSH - Potential Brute Force"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
let threshold = 15;
Syslog
| where SyslogMessage contains "Failed password for invalid user"
| where ProcessName =~ "sshd" 
| parse kind=relaxed SyslogMessage with * "invalid user" user " from " ip " port" port " ssh2"
| project user, ip, port, SyslogMessage, EventTime
| summarize EventTimes = make_list(EventTime), PerHourCount = count() by ip, bin(EventTime, 4h), user
| where PerHourCount > threshold
| mvexpand EventTimes
| extend EventTimes = tostring(EventTimes) 
| summarize StartTimeUtc = min(EventTimes), EndTimeUtc = max(EventTimes), UserList = makeset(user), sum(PerHourCount) by IPAddress = ip
| extend UserList = tostring(UserList) 
| extend timestamp = StartTimeUtc, IPCustomEntity = IPAddress, AccountCustomEntity = UserList
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['CredentialAccess']
  techniques = ['T1110']
  display_name = SSH - Potential Brute Force
  description = <<EOT
Identifies an IP address that had 15 failed attempts to sign in via SSH in a 4 hour block during a 24 hour time period.
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = P1D
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
