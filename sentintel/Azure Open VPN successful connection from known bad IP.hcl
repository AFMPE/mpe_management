resource "my_alert_rule" "rule_232" {
  name = "Azure Open VPN successful connection from known bad IP"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = High
  query = <<EOF
let BlockList = (externaldata(ip:string)
[@"https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
@"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt",
@"https://cinsscore.com/list/ci-badguys.txt",
@"https://infosec.cert-pa.it/analyze/listip.txt",
@"https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
]
with(format="csv")
| where ip matches regex "(^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
| distinct ip
);
AzureDiagnostics
| where TimeGenerated >= ago(5m)
| where Message contains "Connection successful."
| parse Message with * "Username=" * "IP=" SourceIP
| where SourceIP in (BlockList)
| extend IPCustomEntity = SourceIP
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['InitialAccess', 'CredentialAccess']
  techniques = ['T1078']
  display_name = Azure Open VPN successful connection from known bad IP
  description = <<EOT
Checks source of successful connections against lists of malicious IPs.
EOT
  enabled = False
  create_incident = True
  grouping_configuration {
    enabled = True
    reopen_closed_incident = True
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
