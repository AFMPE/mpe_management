resource "my_alert_rule" "rule_286" {
  name = "Whoami process activity"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Low
  query = <<EOF
let SE = (SecurityEvent 
| where EventID == 4688 and Process == "whoami.exe"
| extend HostCustomEntity = Computer, AccountCustomEntity = SubjectUserName
);
let DfE =
(DeviceProcessEvents
| where InitiatingProcessFileName has "cmd.exe"
| where ProcessCommandLine has "whoami"
| where not (InitiatingProcessFileName has_any ("make", "AcrobatUpdaterUninstaller", "qualys-scan-util", "qualys-cloud-agent"))
| where not (InitiatingProcessParentId == 0)
| extend HostCustomEntity = DeviceName, AccountCustomEntity = AccountName
);
SE
| union DfE
| where not(InitiatingProcessParentFileName has_any ("PanGpHip.exe", "ltsvc.exe", "ArcGISPortal.exe", "acslaunch", "javaw.exe"))

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
  }
  tactics = ['Discovery']
  techniques = ['T1033']
  display_name = Whoami process activity
  description = <<EOT
'Identifies use of whoami.exe which displays user, group, and privileges information for the user who is currently logged on to the local system.'

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
