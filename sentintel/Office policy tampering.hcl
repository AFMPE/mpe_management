resource "my_alert_rule" "rule_364" {
  name = "Office policy tampering"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let opList = OfficeActivity 
| summarize by Operation
//| where Operation startswith "Remove-" or Operation startswith "Disable-"
| where Operation has_any ("Remove", "Disable")
| where Operation contains "AntiPhish" or Operation contains "SafeAttachment" or Operation contains "SafeLinks" or Operation contains "Dlp" or Operation contains "Audit"
| summarize make_set(Operation);
OfficeActivity
// Only admin or global-admin can disable/remove policy
| where RecordType =~ "ExchangeAdmin"
| where UserType in~ ("Admin","DcAdmin")
// Pass in interesting Operation list
| where Operation in~ (opList)
| extend ClientIPOnly = case( 
ClientIP has ".", tostring(split(ClientIP,":")[0]), 
ClientIP has "[", tostring(trim_start(@'[[]',tostring(split(ClientIP,"]")[0]))),
ClientIP
)  
| extend Port = case(
ClientIP has ".", (split(ClientIP,":")[1]),
ClientIP has "[", tostring(split(ClientIP,"]:")[1]),
ClientIP
)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), OperationCount = count() by Operation, UserType, UserId, ClientIP = ClientIPOnly, Port, ResultStatus, Parameters
| extend timestamp = StartTimeUtc, AccountCustomEntity = UserId, IPCustomEntity = ClientIP
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
  tactics = ['Persistence', 'DefenseEvasion']
  techniques = ['T1098', 'T1562']
  display_name = Office policy tampering
  description = <<EOT
Identifies if any tampering is done to either auditlog, ATP Safelink, SafeAttachment, AntiPhish or Dlp policy. 
An adversary may use this technique to evade detection or avoid other policy based defenses.
References: https://docs.microsoft.com/powershell/module/exchange/advanced-threat-protection/remove-antiphishrule?view=exchange-ps.
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
