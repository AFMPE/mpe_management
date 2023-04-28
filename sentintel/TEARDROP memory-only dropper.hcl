resource "my_alert_rule" "rule_4" {
  name = "TEARDROP memory-only dropper"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = High
  query = <<EOF
DeviceEvents
| where ActionType has "ExploitGuardNonMicrosoftSignedBlocked"
| where InitiatingProcessFileName contains "svchost.exe" and FileName contains "NetSetupSvc.dll"
| extend timestamp = TimeGenerated, AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
HostCustomEntity = DeviceName, FileHashCustomEntity = InitiatingProcessSHA1, FileHashType = "SHA1"
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
    entity_type = FileHash
    field_mappings {
      identifier = Algorithm
      column_name = FileHashType
      identifier = Value
      column_name = FileHashCustomEntity
    }
  }
  tactics = ['Execution', 'Persistence', 'InitialAccess', 'DefenseEvasion']
  techniques = ['T1059', 'T1543', 'T1027']
  display_name = TEARDROP memory-only dropper
  description = <<EOT
Identifies SolarWinds TEARDROP memory-only dropper IOCs in Window's defender Exploit Guard activity
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = P1D
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
