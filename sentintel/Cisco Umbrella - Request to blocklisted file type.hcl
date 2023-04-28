resource "my_alert_rule" "rule_90" {
  name = "Cisco Umbrella - Request to blocklisted file type"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT10M
  query_period = PT10M
  severity = Medium
  query = <<EOF
let file_ext_blocklist = dynamic(['.ps1', '.vbs', '.bat', '.scr']);
let lbtime = 10m;
Cisco_Umbrella
| where TimeGenerated > ago(lbtime)
| where EventType == 'proxylogs'
| where DvcAction =~ 'Allowed'
| extend file_ext = extract(@'.*(\.\w+)$', 1, UrlOriginal)
| extend Filename = extract(@'.*\/*\/(.*\.\w+)$', 1, UrlOriginal)
| where file_ext in (file_ext_blocklist)
| project TimeGenerated, SrcIpAddr, Identities, Filename
| extend IPCustomEntity = SrcIpAddr
| extend AccountCustomEntity = Identities
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['DefenseEvasion']
  techniques = ['T1071']
  display_name = Cisco Umbrella - Request to blocklisted file type
  description = <<EOT
Detects request to potentially harmful file types (.ps1, .bat, .vbs, etc.).
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
