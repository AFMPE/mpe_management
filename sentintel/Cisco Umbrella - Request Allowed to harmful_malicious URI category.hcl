resource "my_alert_rule" "rule_223" {
  name = "Cisco Umbrella - Request Allowed to harmful_malicious URI category"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT10M
  query_period = PT10M
  severity = Medium
  query = <<EOF
let lbtime = 10m;
Cisco_Umbrella
| where TimeGenerated > ago(lbtime)
| where EventType == 'proxylogs'
| where DvcAction =~ 'Allowed'
| where UrlCategory contains 'Adult Themes' or
      UrlCategory contains 'Adware' or
      UrlCategory contains 'Alcohol' or
      UrlCategory contains 'Illegal Downloads' or
      UrlCategory contains 'Drugs' or
      UrlCategory contains 'Child Abuse Content' or
      UrlCategory contains 'Hate/Discrimination' or
      UrlCategory contains 'Nudity' or
      UrlCategory contains 'Pornography' or
      UrlCategory contains 'Proxy/Anonymizer' or
      UrlCategory contains 'Sexuality' or
      UrlCategory contains 'Tasteless' or
      UrlCategory contains 'Terrorism' or
      UrlCategory contains 'Web Spam' or
      UrlCategory contains 'German Youth Protection' or
      UrlCategory contains 'Illegal Activities' or
      UrlCategory contains 'Lingerie/Bikini' or
      UrlCategory contains 'Weapons'
| project TimeGenerated, SrcIpAddr, Identities
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
  tactics = ['InitialAccess']
  techniques = ['T1192']
  display_name = Cisco Umbrella - Request Allowed to harmful/malicious URI category
  description = <<EOT
It is reccomended that these Categories shoud be blocked by policies because they provide harmful/malicious content..
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
