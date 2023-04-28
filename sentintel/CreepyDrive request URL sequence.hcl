resource "my_alert_rule" "rule_13" {
  name = "CreepyDrive request URL sequence"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = High
  query = <<EOF
let eventsThreshold = 20;
CommonSecurityLog
| where isnotempty(RequestURL)
| project TimeGenerated, RequestURL, RequestMethod, SourceIP, SourceHostName
| evaluate sequence_detect(TimeGenerated, 5s, 8s, login=(RequestURL has "login.microsoftonline.com/consumers/oauth2/v2.0/token"), graph=(RequestURL has "graph.microsoft.com/v1.0/me/drive/"), SourceIP, SourceHostName)
| summarize Events=count() by SourceIP, SourceHostName
| where Events >= eventsThreshold
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = SourceIP
    }
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = SourceHostName
    }
  }
  tactics = ['Exfiltration', 'CommandAndControl']
  techniques = ['T1567', 'T1102']
  display_name = CreepyDrive request URL sequence
  description = <<EOT
CreepyDrive uses OneDrive for command and control, however, it makes regular requests to predicatable paths.
This detecton will alert when over 20 sequences are observed in a single day.
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
