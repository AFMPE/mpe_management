resource "my_alert_rule" "rule_182" {
  name = "External Upstream Source Added to Azure DevOps Feed"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
// Add any known allowed sources and source locations to the filter below (the NuGet Gallery has been added here as an example).
let allowed_sources = dynamic(["NuGet Gallery"]);
let allowed_locations = dynamic(["https://api.nuget.org/v3/index.json"]);
AzureDevOpsAuditing
// Look for feeds created or modified at either the organization or project level
| where OperationName matches regex "Artifacts.Feed.(Org|Project).Modify"
| where Details has "UpstreamSources, added"
| extend FeedName = tostring(Data.FeedName)
| extend FeedId = tostring(Data.FeedId)
| extend UpstreamsAdded = Data.UpstreamsAdded
// As multiple feeds may be added expand these out
| mv-expand UpstreamsAdded
// Only focus on external feeds
| where UpstreamsAdded.UpstreamSourceType !~ "internal"
| extend SourceLocation = tostring(UpstreamsAdded.Location)
| extend SourceName = tostring(UpstreamsAdded.Name)
// Exclude sources and locations in the allow list
| where SourceLocation !in (allowed_locations) and SourceName !in (allowed_sources)
| extend SourceProtocol = tostring(UpstreamsAdded.Protocol)
| extend SourceStatus = tostring(UpstreamsAdded.Status)
| project-reorder TimeGenerated, OperationName, ScopeDisplayName, ProjectName, FeedName, SourceName, SourceLocation, SourceProtocol, ActorUPN, UserAgent, IpAddress
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity =  IpAddress
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
  tactics = ['InitialAccess']
  techniques = ['T1199']
  display_name = External Upstream Source Added to Azure DevOps Feed
  description = <<EOT
The detection looks for new external sources added to an Azure DevOps feed. An allow list can be customized to explicitly allow known good sources. An attacker could look to add a malicious feed in order to inject malicious packages into a build pipeline.
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
