resource "my_alert_rule" "rule_39" {
  name = "Windows host username encoded in base64 web request"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let accountLookback = 3d;
let requestLookback = 3d;
let extraction_regex = @"(?:\?|&)[a-zA-Z0-9\%]*=([a-zA-Z0-9\/\+\=]*)";
// Collect account names and base64 encode them
DeviceEvents
| where TimeGenerated > ago(accountLookback)
| summarize make_set(DeviceId), make_set(DeviceName) by InitiatingProcessAccountName
| where isnotempty(InitiatingProcessAccountName)
| extend base64_user = base64_encode_tostring(InitiatingProcessAccountName)
| join (
    // Collect requests and extract base64 parameters
    CommonSecurityLog
    | where TimeGenerated > ago(requestLookback)
    | where isnotempty(RequestURL)
    // Summarize early on the RequestURL
    | summarize FirstRequest=min(TimeGenerated), LastRequest=max(TimeGenerated), NumberOfRequests=count() by RequestURL
    | extend base64_candidate = extract_all(extraction_regex, RequestURL)
    | mv-expand base64_candidate  to typeof(string)
) on $left.base64_user == $right.base64_candidate
| project FirstRequest, LastRequest, NumberOfRequests, RequestURL, DeviceIds=set_DeviceId, DeviceNames=set_DeviceName, UserName=InitiatingProcessAccountName
EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = DeviceNames
    }
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = RequestURL
    }
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = UserName
    }
  }
  tactics = ['Exfiltration', 'CommandAndControl']
  techniques = ['T1041', 'T1071']
  display_name = Windows host username encoded in base64 web request
  description = <<EOT
This detection will identify network requests in HTTP proxy data that contains Base64 encoded usernames from machines in the DeviceEvents table.
This technique was seen usee by POLONIUM in their RunningRAT tool.
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
