resource "my_alert_rule" "rule_143" {
  name = "CreepyDrive URLs"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = High
  query = <<EOF
let oneDriveCalls = dynamic(['graph.microsoft.com/v1.0/me/drive/root:/Documents/data.txt:/content','graph.microsoft.com/v1.0/me/drive/root:/Documents/response.json:/content']);
let oneDriveCallsRegex = dynamic([@'graph\.microsoft\.com\/v1\.0\/me\/drive\/root\:\/Uploaded\/.*\:\/content',@'graph\.microsoft\.com\/v1\.0\/me\/drive\/root\:\/Downloaded\/.*\:\/content']);
CommonSecurityLog
| where RequestURL has_any (oneDriveCalls) or RequestURL matches regex tostring(oneDriveCallsRegex[0]) or RequestURL matches regex tostring(oneDriveCallsRegex[1])
| project TimeGenerated, DeviceVendor, DeviceProduct, DeviceAction, DestinationDnsDomain, DestinationIP, RequestURL, SourceIP, SourceHostName, RequestClientApplication
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
  display_name = CreepyDrive URLs
  description = <<EOT
CreepyDrive uses OneDrive for command and control. This detection identifies URLs specific to CreepyDrive.
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
