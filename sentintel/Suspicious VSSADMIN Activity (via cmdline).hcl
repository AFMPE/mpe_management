resource "my_alert_rule" "rule_218" {
  name = "Suspicious VSSADMIN Activity (via cmdline)"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
let SE=
(SecurityEvent 
| where EventID == 4688  
| where NewProcessName has "vssadmin.exe" and CommandLine has "shadow" and CommandLine has "delete"
| extend AccountCustomEntity = Account
| extend HostCustomEntity = Computer
);
let DPE=
(DeviceProcessEvents
| where InitiatingProcessCommandLine has "cmd.exe"
| where ProcessCommandLine has "vssadmin" 
| where ProcessCommandLine has "delete"
| extend AccountCustomEntity=AccountName, HostCustomEntity=DeviceName
);
SE
|union DPE
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
  techniques = ['T1552']
  display_name = Suspicious VSSADMIN Activity (via cmdline)
  description = <<EOT
Volume Shadow Copy Deletion can be part of normal sysadmin actions. It can also be a precurser to an impending ransomware attack. 
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = PT5M
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = None
    group_by_custom_details = None
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
