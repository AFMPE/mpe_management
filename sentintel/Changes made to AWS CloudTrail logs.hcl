resource "my_alert_rule" "rule_246" {
  name = "Changes made to AWS CloudTrail logs"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
let EventNameList = dynamic(["UpdateTrail","DeleteTrail","StopLogging","DeleteFlowLogs","DeleteEventBus"]);
AWSCloudTrail
| where EventName in~ (EventNameList)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by EventName, EventTypeName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, 
UserIdentityUserName, SessionMfaAuthenticated, SourceIpAddress, AWSRegion, EventSource
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
  tactics = ['DefenseEvasion']
  techniques = ['T1562']
  display_name = Changes made to AWS CloudTrail logs
  description = <<EOT
Attackers often try to hide their steps by deleting or stopping the collection of logs that could show their activity. 
This alert identifies any manipulation of AWS CloudTrail, Cloudwatch/EventBridge or VPC Flow logs.
More Information: AWS CloudTrail API: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_Operations.html
AWS Cloudwatch/Eventbridge API: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_Operations.html
AWS DelteteFlowLogs API : https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteFlowLogs.html 
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
