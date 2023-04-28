resource "my_alert_rule" "rule_148" {
  name = "Possible Bloodhound and Sharphound Ingestor"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = High
  query = <<EOF
let SE = (SecurityEvent 
| where ((NewProcessName contains "\\Bloodhound.exe" or NewProcessName contains "\\SharpHound.exe") or (CommandLine contains " -CollectionMethod All " or CommandLine contains ".exe -c All -d " or CommandLine contains "Invoke-Bloodhound" or CommandLine contains "Get-BloodHoundData") or (CommandLine contains " -JsonFolder" and CommandLine contains " -ZipFileName ") or (CommandLine contains " DCOnly " and CommandLine contains " --NoSaveCache "))
| extend AccountCustomEntity = Account, HostCustomEntity = Computer);
let DPE = (DeviceProcessEvents
| where ProcessCommandLine has_any ("Bloodhound.exe", "SharpHound.exe", "-CollectionMethod All", ".exe -c All -d", "Invoke-Bloodhound", "Get-BloodHoundData") 
  or ProcessCommandLine has_all ("-JsonFolder","-ZipFileName")
  or ProcessCommandLine has_all ("DCOnly", "--NoSaveCache")
| extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName);
SE
| union DPE
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
  techniques = ['T1046']
  display_name = Possible Bloodhound and Sharphound Ingestor
  description = <<EOT
'Detects command line parameters used by Bloodhound and Sharphound'

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
