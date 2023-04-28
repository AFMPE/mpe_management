resource "my_alert_rule" "rule_263" {
  name = "SUNBURST and SUPERNOVA backdoor hashes"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = High
  query = <<EOF
let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5
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
      column_name = AlgorithmCustomEntity
      identifier = Value
      column_name = FileHashCustomEntity
    }
  }
  tactics = ['Execution', 'Persistence', 'InitialAccess']
  techniques = ['T1195', 'T1059', 'T1546']
  display_name = SUNBURST and SUPERNOVA backdoor hashes
  description = <<EOT
Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
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
    group_by_alert_details = None
    group_by_custom_details = None
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
