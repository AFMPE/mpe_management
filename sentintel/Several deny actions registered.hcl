resource "my_alert_rule" "rule_71" {
  name = "Several deny actions registered"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
let threshold = 1;
AzureDiagnostics
    | where OperationName in ("AzureFirewallApplicationRuleLog","AzureFirewallNetworkRuleLog")
    | extend msg_s_replaced0 = replace(@"\s\s",@" ",msg_s)
    | extend msg_s_replaced1 = replace(@"\.\s",@" ",msg_s_replaced0)
    | extend msg_a = split(msg_s_replaced1," ")
    | extend srcAddr_a = split(msg_a[3],":") , destAddr_a = split(msg_a[5],":")
    | extend protocol = tostring(msg_a[0]), srcIp = tostring(srcAddr_a[0]), srcPort = tostring(srcAddr_a[1]), destIp = tostring(destAddr_a[0]), destPort = tostring(destAddr_a[1]), action = tostring(msg_a[7])
    | where action == "Deny"
    | extend url = iff(destIp matches regex "\\d+\\.\\d+\\.\\d+\\.\\d+","",destIp)
    | summarize StartTime = min(TimeGenerated), count() by srcIp, destIp, url, action, protocol
    | where count_ >= ["threshold"]
    | extend timestamp = StartTime, URLCustomEntity = url, IPCustomEntity = srcIp
EOF
  entity_mapping {
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
  }
  tactics = ['Discovery', 'LateralMovement', 'CommandAndControl']
  techniques = ['T1046', 'T1071', 'T1210']
  display_name = Several deny actions registered
  description = <<EOT
Identifies attack pattern when attacker tries to move, or scan, from resource to resource on the network and creates an incident when a source has more than 1 registered deny action in Azure Firewall.
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
