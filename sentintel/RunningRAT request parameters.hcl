resource "my_alert_rule" "rule_369" {
  name = "RunningRAT request parameters"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = High
  query = <<EOF
let runningRAT_parameters = dynamic(['/ui/chk', 'mactok=', 'UsRnMe=', 'IlocalP=', 'kMnD=']);
CommonSecurityLog
| where RequestMethod == "GET"
| project TimeGenerated, DeviceVendor, DeviceProduct, DeviceAction, DestinationDnsDomain, DestinationIP, RequestURL, SourceIP, SourceHostName, RequestClientApplication
| where RequestURL has_any (runningRAT_parameters)
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = SourceIP
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = DestinationIP
    }
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = SourceHostName
    }
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = RequestURL
    }
  }
  tactics = ['Exfiltration', 'CommandAndControl']
  techniques = ['T1071', 'T1041']
  display_name = RunningRAT request parameters
  description = <<EOT
This detection will alert when RunningRAT URI parameters or paths are detect in an HTTP request. Id the device blocked this communication
presence of this alert means the RunningRAT implant is likely still executing on the source host.
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
