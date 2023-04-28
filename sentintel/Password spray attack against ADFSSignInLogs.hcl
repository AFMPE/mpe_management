resource "my_alert_rule" "rule_276" {
  name = "Password spray attack against ADFSSignInLogs"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT30M
  query_period = PT1H
  severity = Medium
  query = <<EOF
let queryfrequency = 30m;
let accountthreshold = 10;
let successCodes = dynamic([0, 50144]);
ADFSSignInLogs
| extend IngestionTime = ingestion_time()
| where IngestionTime > ago(queryfrequency)
| where not(todynamic(AuthenticationDetails)[0].authenticationMethod == "Integrated Windows Authentication")
| summarize
    DistinctFailureCount = dcountif(UserPrincipalName, ResultType !in (successCodes)),
    DistinctSuccessCount = dcountif(UserPrincipalName, ResultType in (successCodes)),
    SuccessAccounts = make_set_if(UserPrincipalName, ResultType in (successCodes), 250),
    arg_min(TimeGenerated, *)
    by IPAddress
| where DistinctFailureCount > DistinctSuccessCount and DistinctFailureCount >= accountthreshold
//| extend SuccessAccounts = iff(array_length(SuccessAccounts) != 0, SuccessAccounts, dynamic(["null"]))
//| mv-expand SuccessAccounts
| project TimeGenerated, Category, OperationName, IPAddress, DistinctFailureCount, DistinctSuccessCount, SuccessAccounts, AuthenticationRequirement, ConditionalAccessStatus, IsInteractive, UserAgent, NetworkLocationDetails, DeviceDetail, TokenIssuerType, TokenIssuerName, ResourceIdentity
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPAddress
    }
  }
  tactics = ['CredentialAccess']
  techniques = ['T1110']
  display_name = Password spray attack against ADFSSignInLogs
  description = <<EOT
Identifies evidence of password spray activity against Connect Health for AD FS sign-in events by looking for failures from multiple accounts from the same IP address within a time window.
Reference: https://adfshelp.microsoft.com/References/ConnectHealthErrorCodeReference
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
