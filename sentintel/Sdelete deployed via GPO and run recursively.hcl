resource "my_alert_rule" "rule_355" {
  name = "Sdelete deployed via GPO and run recursively"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
SecurityEvent
  | where EventID == 4688
  | where Process =~ "svchost.exe"
  | where CommandLine has "-k GPSvcGroup" or CommandLine has "-s gpsvc"
  | extend timekey = bin(TimeGenerated, 1m)
  | project timekey, NewProcessId, Computer
  | join kind=inner (SecurityEvent
  | where EventID == 4688
  | where Process =~ "sdelete.exe" or CommandLine has "sdelete"
  | where ParentProcessName endswith "svchost.exe"
  | where CommandLine has_all ("-s", "-r")
  | extend newProcess = Process
  | extend timekey = bin(TimeGenerated, 1m)
  ) on $left.NewProcessId == $right.ProcessId, timekey, Computer
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = Account
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = Computer
    }
  }
  tactics = ['Impact']
  techniques = ['T1485']
  display_name = Sdelete deployed via GPO and run recursively
  description = <<EOT
This query looks for the Sdelete process being run recursively after being deployed to a host via GPO. Attackers could use this technique to deploy Sdelete to multiple host and delete data on them.
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
