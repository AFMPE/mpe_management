resource "my_alert_rule" "rule_233" {
  name = "Dormant Service Principal Update Creds and Logs In"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
let starttime = todatetime('{{StartTimeISO}}');
let endtime = todatetime('{{EndTimeISO}}');
let lookback = endtime - 14d;
let sp_active_users = AADServicePrincipalSignInLogs
| where TimeGenerated between(lookback..starttime)
| where ResultType  == 0
| summarize by ServicePrincipalId;
AuditLogs
| where TimeGenerated between(starttime..endtime)
// Looking for new creds added to an SP rather than MFA
| where OperationName in ("Add service principal credentials", "Update application - Certificates and secrets management")
| extend ServicePrincipalId = tostring(TargetResources[0].id)
| where ServicePrincipalId !in (sp_active_users)
| join kind=inner (SigninLogs | where TimeGenerated between(starttime..endtime) | where ResultType == 0) on ServicePrincipalId
| extend AccountCustomEntity = ServicePrincipalId, IPCustomEntity = IPAddress

EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = AadUserId
      column_name = AccountCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['Persistence']
  techniques = ['T1098']
  display_name = Dormant Service Principal Update Creds and Logs In
  description = <<EOT
'This query look for Service Principal accounts that are no longer used where a user has added or updated credentials for them before logging in with the Service Principal.
 Threat actors may look to re-activate dormant accounts and use them for access in the hope that changes to such dormant accounts may go un-noticed.'

EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5M
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
