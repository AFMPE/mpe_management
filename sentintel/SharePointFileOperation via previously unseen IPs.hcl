resource "my_alert_rule" "rule_305" {
  name = "SharePointFileOperation via previously unseen IPs"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Medium
  query = <<EOF
let threshold = 50;
let szSharePointFileOperation = "SharePointFileOperation";
let szOperations = dynamic(["FileDownloaded", "FileUploaded"]);
let starttime = 14d;
let endtime = 1d;
let historicalActivity =
OfficeActivity
| where TimeGenerated between(ago(starttime)..ago(endtime))
| where RecordType =~ szSharePointFileOperation
| where Operation in~ (szOperations)
| summarize historicalCount = count() by ClientIP, RecordType, Operation;
let recentActivity = OfficeActivity
| where TimeGenerated > ago(endtime)
| where RecordType =~ szSharePointFileOperation
| where Operation in~ (szOperations)
| summarize min(Start_Time), max(Start_Time), recentCount = count() by ClientIP, RecordType, Operation;
let RareIP = recentActivity | join kind= leftanti ( historicalActivity ) on ClientIP, RecordType, Operation
// More than 50 downloads/uploads from a new IP
| where recentCount > threshold;
OfficeActivity 
| where TimeGenerated >= ago(endtime) 
| where RecordType =~ szSharePointFileOperation
| where Operation in~ (szOperations)
| join kind= inner (RareIP) on ClientIP, RecordType, Operation
| where Start_Time between(min_Start_Time .. max_Start_Time)
| summarize Files = make_set(OfficeObjectId) by Operation, UserType, UserId, ClientIP, OfficeWorkload, UserAgent, Site_Url
| extend AccountCustomEntity = UserId, IPCustomEntity = ClientIP, URLCustomEntity = Site_Url
| order by ClientIP asc, Operation asc, UserId asc
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
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = URLCustomEntity
    }
  }
  tactics = ['Exfiltration']
  techniques = ['T1030']
  display_name = SharePointFileOperation via previously unseen IPs
  description = <<EOT
Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses
exceeds a threshold (default is 50).
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
    reopen_closed_incident = False
    lookback_duration = P1D
    entity_matching_method = Selected
    group_by_entities = ['IP', 'Account']
    group_by_alert_details = ['DisplayName']
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'AlertPerResult'}
}
