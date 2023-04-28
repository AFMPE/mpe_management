resource "my_alert_rule" "rule_181" {
  name = "Microsoft Build Engine Started by an Office Application"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
union
(SecurityEvent
| where Channel == "Security"
| where AccountType == "User"
| where EventID == "4688"
| where Process == "MSBuild.exe"
| where ParentProcessName has_any ("eqnedt32.exe", "excel.exe", "fltldr.exe", "msaccess.exe", "mspub.exe", "outlook.exe", "powerpnt.exe", "winword.exe")
| extend AccountCustomEntity = Account, HostCustomEntity = Computer
),
(DeviceProcessEvents
| where FileName has "MSBuild.exe"
| where InitiatingProcessFileName has_any ("eqnedt32.exe", "excel.exe", "fltldr.exe", "msaccess.exe", "mspub.exe", "outlook.exe", "powerpnt.exe", "winword.exe")
| extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName)
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
  tactics = ['DefenseEvasion', 'Execution']
  techniques = ['T1036']
  display_name = Microsoft Build Engine Started by an Office Application
  description = <<EOT
'An instance of MSBuild, the Microsoft Build Engine, was started by Excel or Word. This is unusual behavior for the Build Engine and could have been caused by an Excel or Word document executing a malicious script payload.'

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
