resource "my_alert_rule" "rule_107" {
  name = "Changes to AWS Security Group ingress and egress settings"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
let EventNameList = dynamic([ "AuthorizeSecurityGroupEgress", "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupEgress", "RevokeSecurityGroupIngress"]);
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
  display_name = Changes to AWS Security Group ingress and egress settings
  description = <<EOT
A Security Group acts as a virtual firewall of an instance to control inbound and outbound traffic. 
 Hence, ingress and egress settings changes to AWS Security Group should be monitored as these can expose the enviornment to new attack vectors.
More information: https://medium.com/@GorillaStack/the-most-important-aws-cloudtrail-security-events-to-track-a5b9873f8255.
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
