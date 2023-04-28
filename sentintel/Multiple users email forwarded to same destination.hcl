resource "my_alert_rule" "rule_320" {
  name = "Multiple users email forwarded to same destination"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P7D
  severity = Medium
  query = <<EOF
let queryfrequency = 1d;
let queryperiod = 7d;
OfficeActivity
| where TimeGenerated > ago(queryperiod)
| where OfficeWorkload =~ "Exchange"
//| where Operation in ("Set-Mailbox", "New-InboxRule", "Set-InboxRule")
| where Parameters has_any ("ForwardTo", "RedirectTo", "ForwardingSmtpAddress")
| mv-apply DynamicParameters = todynamic(Parameters) on (summarize ParsedParameters = make_bag(pack(tostring(DynamicParameters.Name), DynamicParameters.Value)))
| evaluate bag_unpack(ParsedParameters, columnsConflict='replace_source')
| extend DestinationMailAddress = tolower(case(
    isnotempty(column_ifexists("ForwardTo", "")), column_ifexists("ForwardTo", ""),
    isnotempty(column_ifexists("RedirectTo", "")), column_ifexists("RedirectTo", ""),
    isnotempty(column_ifexists("ForwardingSmtpAddress", "")), trim_start(@"smtp:", column_ifexists("ForwardingSmtpAddress", "")),
    ""))
| where isnotempty(DestinationMailAddress)
| mv-expand split(DestinationMailAddress, ";")
| extend ClientIPValues = extract_all(@'\[?(::ffff:)?(?P<IPAddress>(\d+\.\d+\.\d+\.\d+)|[^\]]+)\]?([-:](?P<Port>\d+))?', dynamic(["IPAddress", "Port"]), ClientIP)[0]
| extend ClientIP = tostring(ClientIPValues[0]), Port = tostring(ClientIPValues[1])
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), DistinctUserCount = dcount(UserId), UserId = make_set(UserId, 250), Ports = make_set(Port, 250), EventCount = count() by tostring(DestinationMailAddress), ClientIP
| where DistinctUserCount > 1 and EndTime > ago(queryfrequency)
| mv-expand UserId to typeof(string)
| extend timestamp = StartTime, AccountCustomEntity = UserId, IPCustomEntity = ClientIP
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
  display_name = Multiple users email forwarded to same destination
  description = <<EOT
Identifies when multiple (more than one) users mailboxes are configured to forward to the same destination. 
This could be an attacker-controlled destination mailbox configured to collect mail from multiple compromised user accounts.
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
