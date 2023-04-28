resource "my_alert_rule" "rule_278" {
  name = "Front Door Premium WAF - XSS Detection"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT6H
  query_period = PT6H
  severity = High
  query = <<EOF
let Threshold = 1;
AzureDiagnostics
| where Category == "FrontDoorWebApplicationFirewallLog"
| where action_s == "AnomalyScoring"
| where details_msg_s contains "XSS"
| parse details_data_s with MessageText "Matched Data:" MatchedData "AND " * "table_name FROM " TableName " " *
| project trackingReference_s, host_s, requestUri_s, TimeGenerated, clientIP_s, details_matches_s, details_msg_s, details_data_s, TableName, MatchedData
| join kind = inner(
AzureDiagnostics
| where Category == "FrontDoorWebApplicationFirewallLog"
| where action_s == "Block") on trackingReference_s
| summarize URI_s = make_set(requestUri_s), Table = make_set(TableName), StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), TrackingReference = make_set(trackingReference_s), Matched_Data = make_set(MatchedData), Detail_Data = make_set(details_data_s), Detail_Message = make_set(details_msg_s), Total_TrackingReference = dcount(trackingReference_s) by clientIP_s, host_s, action_s
| where Total_TrackingReference >= Threshold
EOF
  entity_mapping {
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = URI_s
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = clientIP_s
    }
  }
  tactics = ['InitialAccess', 'Execution']
  techniques = ['T189', 'T1203', 'T0853']
  display_name = Front Door Premium WAF - XSS Detection
  description = <<EOT
Identifies a match for XSS attack in the Front Door Premium WAF logs. The Threshold value in the query can be changed as per your infrastructure's requirement.
 References: https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)
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
