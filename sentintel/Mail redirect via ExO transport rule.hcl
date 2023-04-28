resource "my_alert_rule" "rule_244" {
  name = "Mail redirect via ExO transport rule"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
OfficeActivity
| where OfficeWorkload == "Exchange"
| where Operation in~ ("New-TransportRule", "Set-TransportRule")
| mv-apply DynamicParameters = todynamic(Parameters) on (summarize ParsedParameters = make_bag(pack(tostring(DynamicParameters.Name), DynamicParameters.Value)))
| extend RuleName = case(
    Operation =~ "Set-TransportRule", OfficeObjectId,
    Operation =~ "New-TransportRule", ParsedParameters.Name,
    "Unknown")
| mv-expand ExpandedParameters = todynamic(Parameters)
| where ExpandedParameters.Name in~ ("BlindCopyTo", "RedirectMessageTo") and isnotempty(ExpandedParameters.Value)
| extend RedirectTo = ExpandedParameters.Value
| extend ClientIPValues = extract_all(@'\[?(::ffff:)?(?P<IPAddress>(\d+\.\d+\.\d+\.\d+)|[^\]]+)\]?([-:](?P<Port>\d+))?', dynamic(["IPAddress", "Port"]), ClientIP)[0]
| project TimeGenerated, RedirectTo, IPAddress = tostring(ClientIPValues[0]), Port = tostring(ClientIPValues[1]), UserId, Operation, RuleName, Parameters
| extend timestamp = TimeGenerated, AccountCustomEntity = UserId, IPCustomEntity = IPAddress
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
  tactics = ['Collection', 'Exfiltration']
  techniques = ['T1114', 'T1020']
  display_name = Mail redirect via ExO transport rule
  description = <<EOT
Identifies when Exchange Online transport rule configured to forward emails.
This could be an adversary mailbox configured to collect mail from multiple user accounts.
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
