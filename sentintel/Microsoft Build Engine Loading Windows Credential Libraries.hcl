resource "my_alert_rule" "rule_365" {
  name = "Microsoft Build Engine Loading Windows Credential Libraries"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
union(SecurityEvent
| where Channel == "Security"
| where AccountType == "User"
| where EventID == "4688"
| where Process == "MSBuild.exe"
| where CommandLine has "vaultcli.dll" or CommandLine has "SAMLib.DLL"
| extend AccountCustomEntity = Account, HostCustomEntity = Computer
),
(DeviceProcessEvents
| where FileName has "MSBuild.exe"
| where ProcessCommandLine has_any ("vaultcli.dll", "SAMLib.DLL")
| extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName
)
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
  tactics = ['CredentialAccess']
  techniques = ['T1555']
  display_name = Microsoft Build Engine Loading Windows Credential Libraries
  description = <<EOT
'An instance of MSBuild, the Microsoft Build Engine, loaded DLLs (dynamically linked libraries) responsible for Windows credential management. This technique is sometimes used for credential dumping.'

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
