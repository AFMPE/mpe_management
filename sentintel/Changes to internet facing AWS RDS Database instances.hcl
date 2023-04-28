resource "my_alert_rule" "rule_56" {
  name = "Changes to internet facing AWS RDS Database instances"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
let EventNameList = dynamic(["AuthorizeDBSecurityGroupIngress","CreateDBSecurityGroup","DeleteDBSecurityGroup","RevokeDBSecurityGroupIngress"]);
AWSCloudTrail
| where EventName in~ (EventNameList)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by EventName, EventTypeName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, UserIdentityUserName, SessionMfaAuthenticated, SourceIpAddress, AWSRegion, EventSource, AdditionalEventData, ResponseElements
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
  tactics = ['Persistence']
  techniques = ['T1098']
  display_name = Changes to internet facing AWS RDS Database instances
  description = <<EOT
Amazon Relational Database Service (RDS) is scalable relational database in the cloud. 
If your organization have one or more AWS RDS Databases running, monitoring changes to especially internet facing AWS RDS (Relational Database Service) 
Once alerts triggered, validate if changes observed are authorized and adhere to change control policy. 
More information: https://medium.com/@GorillaStack/the-most-important-aws-cloudtrail-security-events-to-track-a5b9873f8255
and RDS API Reference Docs: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_Operations.html
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
