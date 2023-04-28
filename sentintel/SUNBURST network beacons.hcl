resource "my_alert_rule" "rule_128" {
  name = "SUNBURST network beacons"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let SunburstURL=dynamic(["panhardware.com","databasegalore.com","avsvmcloud.com","freescanonline.com","thedoccloud.com","deftsecurity.com"]);
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemoteUrl in(SunburstURL)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    FileHashCustomEntity = InitiatingProcessMD5, 
    HashAlgorithm = 'MD5',
    URLCustomEntity = RemoteUrl,
    IPCustomEntity = RemoteIP
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
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = URLCustomEntity
    }
    entity_type = FileHash
    field_mappings {
      identifier = Algorithm
      column_name = HashAlgorithm
      identifier = Value
      column_name = FileHashCustomEntity
    }
  }
  tactics = ['Execution', 'Persistence', 'InitialAccess']
  techniques = ['T1195', 'T1059', 'T1546']
  display_name = SUNBURST network beacons
  description = <<EOT
Identifies SolarWinds SUNBURST domain beacon IOCs in DeviceNetworkEvents
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
