resource "my_alert_rule" "rule_228" {
  name = "Encoding or Decoding Files via CertUtil"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = High
  query = <<EOF
let SE = (SecurityEvent
| where Channel == "Security"
| where EventID == "4688"
| where AccountType == "User"
| where Process == "certutil.exe"
| where CommandLine has_any ("encode", "decode", "urlcache")
| extend AccountCustomEntity = Account, HostCustomEntity = Computer
);
let DfE = (DeviceProcessEvents
| where FileName has "certutil.exe"
| where ProcessCommandLine has_any ("encode", "decode", "urlcache")
| extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, AccountCustomEntity, HostCustomEntity
);
SE
| union DfE
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
  tactics = ['CommandAndControl']
  techniques = ['T1132']
  display_name = Encoding or Decoding Files via CertUtil
  description = <<EOT
'Identifies the use of certutil.exe to encode or decode data. CertUtil is a native Windows component which is part of Certificate Services. CertUtil is often abused by attackers to encode or decode base64 data for stealthier command and control or exfiltration.''

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
