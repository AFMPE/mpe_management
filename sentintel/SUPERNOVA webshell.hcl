resource "my_alert_rule" "rule_78" {
  name = "SUPERNOVA webshell"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = High
  query = <<EOF
W3CIISLog
| where csMethod == 'GET'
| where isnotempty(csUriStem) and isnotempty(csUriQuery)
| where csUriStem contains "logoimagehandler.ashx"
| where csUriQuery contains "codes" and csUriQuery contains "clazz" and csUriQuery contains "method" and csUriQuery contains "args"
| extend timestamp = TimeGenerated, IPCustomEntity = cIP, HostCustomEntity = Computer, AccountCustomEntity = csUserName
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
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['Persistence', 'CommandAndControl']
  techniques = ['T1071', 'T1505']
  display_name = SUPERNOVA webshell
  description = <<EOT
Identifies SUPERNOVA webshell based on W3CIISLog data.
 References:
 - https://unit42.paloaltonetworks.com/solarstorm-supernova/
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = P1D
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = None
    group_by_custom_details = None
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
