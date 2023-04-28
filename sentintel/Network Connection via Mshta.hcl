resource "my_alert_rule" "rule_293" {
  name = "Network Connection via Mshta"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = High
  query = <<EOF
DeviceNetworkEvents
| where InitiatingProcessFileName has "mshta.exe"
| extend
    AccountCustomEntity = InitiatingProcessAccountName,
    HostCustomEntity = DeviceName,
    CommandLine = InitiatingProcessCommandLine
| where not (CommandLine has_any("Amazon Assistant", "manageExceptionLogs"))
| where not (RemoteUrl has_any ("ocsp.digicert.com"))
| where not (InitiatingProcessParentFileName has_any("TeamViewer.exe"))
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = AccountCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = HostCustomEntity
    }
    entity_type = Process
    field_mappings {
      identifier = CommandLine
      column_name = CommandLine
    }
  }
  tactics = ['Execution']
  techniques = ['T1059']
  display_name = Network Connection via Mshta
  description = <<EOT
'Identifies mshta.exe making a network connection. This may indicate adversarial activity as mshta.exe is often leveraged by adversaries to execute malicious scripts and evade detection.'

EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5M
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
