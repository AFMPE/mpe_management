resource "my_alert_rule" "rule_115" {
  name = "Adding Hidden File Attribute via Attrib"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
let SE = (
SecurityEvent
| where AccountType == "User"
| where Channel == "Security"
| where EventID == "4688"
| where Process == "attrib.exe" and CommandLine has "+h"
| extend AccountCustomEntity = Account, HostCustomEntity = Computer
);
let DfE = (
DeviceProcessEvents
| where FileName has "attrib.exe" and ProcessCommandLine has "+h" 
| extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName
);
SE
| union DfE
| where not(InitiatingProcessParentFileName has_any ("igfxCUIService.exe", "runkbot.exe"))
| where not(ProcessCommandLine has_any ("cui", "intel", "desktop.ini"))
| where not(InitiatingProcessCommandLine has_any ("C:\\swsetup"))
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
  tactics = ['DefenseEvasion', 'Persistence']
  techniques = ['T1564']
  display_name = Adding Hidden File Attribute via Attrib
  description = <<EOT
'Users can mark specific files as hidden by using the attrib.exe binary. Simply do attrib +h filename to mark a file or folder as hidden. Similarly,
 the "+s" marks a file as a system file and the "+r" flag marks the file as read only. Like most windows binaries,
 the attrib.exe binary provides the ability to apply these changes recursively "/S'

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
