resource "my_alert_rule" "rule_315" {
  name = "Azure DevOps Administrator Group Monitoring"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT4H
  query_period = PT4H
  severity = Medium
  query = <<EOF
// Change to true to monitor for Project Administrator adds to *any* project
let MonitorAllProjects = false;
// If MonitorAllProjects is false, trigger only on Project Administrator add for the following projects
let ProjectsToMonitor = dynamic(['<project_X>','<project_Y>']);
AzureDevOpsAuditing
| where Area == "Group" and OperationName == "Group.UpdateGroupMembership.Add"
| where Details has 'Administrators'
| where Details has "was added as a member of group" and (Details endswith '\\Project Administrators' or Details endswith '\\Project Collection Administrators')
| parse Details with AddedIdentity ' was added as a member of group [' EntityName ']\\' GroupName
| extend Level = iif(GroupName == 'Project Collection Administrators', 'Organization', 'Project'), AddedIdentityId = Data.MemberId
| extend Severity = iif(Level == 'Organization', 'High', 'Medium'), AlertDetails = strcat('At ', TimeGenerated, ' UTC ', ActorUPN, '/', ActorDisplayName, ' added ', AddedIdentity, ' to the ', EntityName, ' ', Level)
| where MonitorAllProjects == true or EntityName in (ProjectsToMonitor) or Level == 'Organization'
| project TimeGenerated, Severity, Adder = ActorUPN, AddedIdentity, AddedIdentityId, AlertDetails, Level, EntityName, GroupName, ActorAuthType = AuthenticationMechanism, 
  ActorIpAddress = IpAddress, ActorUserAgent = UserAgent, RawDetails = Details
| extend timestamp = TimeGenerated, AccountCustomEntity = Adder, IPCustomEntity = ActorIpAddress
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
  display_name = Azure DevOps Administrator Group Monitoring
  description = <<EOT
This detection monitors for additions to projects or project collection administration groups in an Azure DevOps Organization.
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
