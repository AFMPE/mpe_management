resource "my_alert_rule" "rule_198" {
  name = "Unusual Process Network Connection"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Low
  query = <<EOF
DeviceNetworkEvents
| where RemoteIP !has "127.0.0.1"
| where InitiatingProcessCommandLine has_any ("Microsoft.Workflow.Compiler.exe", "bginfo.exe", "cdb.exe", "cmstp.exe", "csi.exe","dnx.exe","fsi.exe", "ieexec.exe", "iexpress.exe", "odbcconf.exe", "rcsi.exe", "xwizard.exe")
| project-rename Computer=DeviceName, Account=InitiatingProcessAccountName, CommandLine=InitiatingProcessCommandLine, GrandParentProcess=InitiatingProcessParentFileName
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = Account
    }
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = Computer
    }
    entity_type = Process
    field_mappings {
      identifier = CommandLine
      column_name = GrandParentProcess
    }
  }
  tactics = ['Execution']
  techniques = ['T1059']
  display_name = Unusual Process Network Connection
  description = <<EOT
'Identifies network activity from unexpected system applications. This may indicate adversarial activity as these applications are often leveraged by adversaries to execute code and evade detection.'

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
