resource "my_alert_rule" "rule_251" {
  name = "Changes to AWS Elastic Load Balancer security groups"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
let EventNameList = dynamic(["ApplySecurityGroupsToLoadBalancer", "SetSecurityGroups"]);
AWSCloudTrail
| where EventName in~ (EventNameList)
| extend User = iif(isnotempty(UserIdentityUserName), UserIdentityUserName, SessionIssuerUserName)
| summarize EventCount=count(), StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) 
by EventSource, EventName, UserIdentityType, User, SourceIpAddress, UserAgent, SessionMfaAuthenticated, AWSRegion,
AdditionalEventData, UserIdentityAccountId, UserIdentityPrincipalid, ResponseElements
| extend timestamp = StartTimeUtc, AccountCustomEntity = User , IPCustomEntity = SourceIpAddress
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
  display_name = Changes to AWS Elastic Load Balancer security groups
  description = <<EOT
Elastic Load Balancer distributes incoming traffic across multiple instances in multiple availability Zones. This increases the fault tolerance of your applications. 
 Unwanted changes to Elastic Load Balancer specific security groups could open your environment to attack and  hence needs monitoring.
 More information: https://medium.com/@GorillaStack/the-most-important-aws-cloudtrail-security-events-to-track-a5b9873f8255 
 and https://aws.amazon.com/elasticloadbalancing/.
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
