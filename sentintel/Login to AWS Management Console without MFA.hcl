resource "my_alert_rule" "rule_336" {
  name = "Login to AWS Management Console without MFA"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
AWSCloudTrail
| where EventName =~ "ConsoleLogin" 
| extend MFAUsed = tostring(parse_json(AdditionalEventData).MFAUsed), LoginResult = tostring(parse_json(ResponseElements).ConsoleLogin)
| where MFAUsed !~ "Yes" and LoginResult !~ "Failure"
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by EventName, EventTypeName, LoginResult, MFAUsed, UserIdentityAccountId,  UserIdentityPrincipalid, UserAgent, 
UserIdentityUserName, SessionMfaAuthenticated, SourceIpAddress, AWSRegion
| extend timestamp = StartTimeUtc, AccountCustomEntity = UserIdentityUserName, IPCustomEntity = SourceIpAddress
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
  tactics = ['DefenseEvasion', 'PrivilegeEscalation', 'Persistence', 'InitialAccess']
  techniques = ['T1078']
  display_name = Login to AWS Management Console without MFA
  description = <<EOT
Multi-Factor Authentication (MFA) helps you to prevent credential compromise. This alert identifies logins to the AWS Management Console without MFA.
You can limit this detection to trigger for adminsitrative accounts if you do not have MFA enabled on all accounts.
This is done by looking at the eventName ConsoleLogin and if the AdditionalEventData field indicates MFA was NOT used 
and the ResponseElements field indicates NOT a Failure. Thereby indicating that a non-MFA login was successful.
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
