resource "my_alert_rule" "rule_160" {
  name = "Anonymizer Tools Detected (via office365)"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5H
  query_period = PT5H
  severity = Medium
  query = <<EOF
OfficeActivity 
| where ((Operation == "FileUploaded" or Operation == "FileAccessed" or Operation == "FileDownloaded") and (SourceFileName has_any ("tbear", "i2p", "torbrowser", "tor.exe")))
| extend AccountCustomEntity = UserId, IPCustomEntity = ClientIP, UrlCustomEntity = Site_Url
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = UrlCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['DefenseEvasion', 'CommandAndControl']
  techniques = ['T1562', 'T1102']
  display_name = Anonymizer Tools Detected (via office365)
  description = <<EOT
An anonymizer or an anonymous proxy is a tool that attempts to make activity on the Internet untraceable. Technique: T1204.
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
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
