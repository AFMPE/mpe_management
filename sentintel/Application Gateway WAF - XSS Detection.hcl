resource "my_alert_rule" "rule_180" {
  name = "Application Gateway WAF - XSS Detection"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT6H
  query_period = PT6H
  severity = High
  query = <<EOF
let Threshold = 1;  
 AzureDiagnostics
 | where Category == "ApplicationGatewayFirewallLog"
 | where action_s == "Matched"
 | project transactionId_g, hostname_s, requestUri_s, TimeGenerated, clientIp_s, Message, details_message_s, details_data_s
 | join kind = inner(
 AzureDiagnostics
 | where Category == "ApplicationGatewayFirewallLog"
 | where action_s == "Blocked"
 | parse Message with MessageText 'Total Inbound Score: ' TotalInboundScore ' - SQLI=' SQLI_Score ',XSS=' XSS_Score ',RFI=' RFI_Score ',LFI=' LFI_Score ',RCE=' RCE_Score ',PHPI=' PHPI_Score ',HTTP=' HTTP_Score ',SESS=' SESS_Score '): ' Blocked_Reason '; individual paranoia level scores:' Paranoia_Score
 | where Blocked_Reason contains "XSS" and toint(TotalInboundScore) >=15 and toint(XSS_Score) >= 10 and toint(SQLI_Score) <= 5) on transactionId_g
 | extend Uri = strcat(hostname_s,requestUri_s)
 | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), TransactionID = make_set(transactionId_g), Message = make_set(Message), Detail_Message = make_set(details_message_s), Detail_Data = make_set(details_data_s), Total_TransactionId = dcount(transactionId_g) by clientIp_s, Uri, action_s, SQLI_Score, XSS_Score, TotalInboundScore
 | where Total_TransactionId >= Threshold
EOF
  entity_mapping {
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = Uri
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = clientIp_s
    }
  }
  tactics = ['InitialAccess', 'Execution']
  techniques = ['T1189', 'T1203', 'T0853']
  display_name = Application Gateway WAF - XSS Detection
  description = <<EOT
Identifies a match for XSS attack in the Application gateway WAF logs. The Threshold value in the query can be changed as per your infrastructure's requirement.
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
