resource "my_alert_rule" "rule_234" {
  name = "Monitor AWS Credential abuse or hijacking"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
AWSCloudTrail
| where EventName =~ "GetCallerIdentity" and UserIdentityType =~ "AssumedRole" 
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by SourceIpAddress, EventName, EventTypeName, UserIdentityType, UserIdentityAccountId, UserIdentityPrincipalid, 
UserAgent, UserIdentityUserName, SessionMfaAuthenticated,AWSRegion, EventSource, AdditionalEventData, ResponseElements
| extend timestamp = StartTime, AccountCustomEntity = UserIdentityUserName, IPCustomEntity = SourceIpAddress
| sort by EndTime desc nulls last
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
  tactics = ['Discovery']
  techniques = ['T1087']
  display_name = Monitor AWS Credential abuse or hijacking
  description = <<EOT
Looking for GetCallerIdentity Events where the UserID Type is AssumedRole 
An attacker who has assumed the role of a legitimate account can call the GetCallerIdentity function to determine what account they are using.
A legitimate user using legitimate credentials would not need to call GetCallerIdentity since they should already know what account they are using.
More Information: https://duo.com/decipher/trailblazer-hunts-compromised-credentials-in-aws
AWS STS GetCallerIdentity API: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html 
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
