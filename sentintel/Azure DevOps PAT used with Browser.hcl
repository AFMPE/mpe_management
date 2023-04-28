resource "my_alert_rule" "rule_42" {
  name = "Azure DevOps PAT used with Browser"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
AzureDevOpsAuditing
| where AuthenticationMechanism startswith "PAT"
// Look for useragents that include a redenring engine
| where UserAgent has_any ("Gecko", "WebKit", "Presto", "Trident", "EdgeHTML", "Blink")
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress
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
  tactics = ['CredentialAccess']
  techniques = ['T1056']
  display_name = Azure DevOps PAT used with Browser
  description = <<EOT
Personal Access Tokens (PATs) are used as an alternate password to authenticate into Azure DevOps. PATs are intended for programmatic access use in code or applications. 
This can be prone to attacker theft if not adequately secured. This query looks for the use of a PAT in authentication but from a User Agent indicating a browser. 
This should not be normal activity and could be an indicator of an attacker using a stolen PAT.
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
