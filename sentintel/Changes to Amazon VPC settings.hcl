resource "my_alert_rule" "rule_19" {
  name = "Changes to Amazon VPC settings"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
let EventNameList = dynamic(["CreateNetworkAclEntry","CreateRoute","CreateRouteTable","CreateInternetGateway","CreateNatGateway"]);
AWSCloudTrail
| where EventName in~ (EventNameList)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by EventName, EventTypeName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, 
UserIdentityUserName, SessionMfaAuthenticated, SourceIpAddress, AWSRegion, EventSource, AdditionalEventData, ResponseElements
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
  tactics = ['PrivilegeEscalation', 'LateralMovement']
  techniques = ['T1078', 'T1563']
  display_name = Changes to Amazon VPC settings
  description = <<EOT
Amazon Virtual Private Cloud (Amazon VPC) lets you provision a logically isolated section of the AWS Cloud where you can launch AWS resources
in a virtual network that you define.
This identifies changes to Amazon VPC (Virtual Private Cloud) settings such as new ACL entries,routes, routetable or Gateways.
More information: https://medium.com/@GorillaStack/the-most-important-aws-cloudtrail-security-events-to-track-a5b9873f8255 
and AWS VPC API Docs: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/OperationList-query-vpc.html
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
