resource "my_alert_rule" "rule_80" {
  name = "Network endpoint to host executable correlation"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let endpointData = 
(union isfuzzy=true
(SecurityEvent
  | where EventID == 4688
  | extend shortFileName = tostring(split(NewProcessName, '\\')[-1])
  ),
  (WindowsEvent
  | where EventID == 4688
  | extend  NewProcessName = tostring(EventData.NewProcessName)
  | extend shortFileName = tostring(split(NewProcessName, '\\')[-1])
  | extend TargetUserName = tostring(EventData.TargetUserName)
  ));
// Correlate suspect executables seen in TrendMicro rule updates with similar activity on endpoints
CommonSecurityLog
| where DeviceVendor =~ "Trend Micro"
| where Activity =~ "Deny List updated" 
| where RequestURL endswith ".exe"
| project TimeGenerated, Activity , RequestURL , SourceIP, DestinationIP
| extend suspectExeName = tolower(tostring(split(RequestURL, '/')[-1]))
| join (endpointData) on $left.suspectExeName == $right.shortFileName 
| extend timestamp = TimeGenerated, IPCustomEntity = DestinationIP, AccountCustomEntity = TargetUserName, HostCustomEntity = Computer, URLCustomEntity = RequestURL
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
  tactics = ['Execution']
  techniques = ['T1204']
  display_name = Network endpoint to host executable correlation
  description = <<EOT
Correlates blocked URLs hosting [malicious] executables with host endpoint data
to identify potential instances of executables of the same name having been recently run.
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
