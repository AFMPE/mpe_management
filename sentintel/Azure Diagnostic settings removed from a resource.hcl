resource "my_alert_rule" "rule_301" {
  name = "Azure Diagnostic settings removed from a resource"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT2H
  severity = Medium
  query = <<EOF
AzureActivity
  | where OperationNameValue == 'MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE' and ActivityStatusValue == "Start"
  | extend ParentResource_a = split(_ResourceId,"/")
  | extend ParentResourceLength = array_length(ParentResource_a)-4
  | extend ParentResourceSplit = array_split(ParentResource_a,ParentResourceLength)
  | extend resource = strcat_array(ParentResourceSplit[0],"/")
  | project Diagdelete = TimeGenerated, Caller, ResourceProviderValue, _ResourceId, SubscriptionId, ResourceGroup, OperationNameValue, ActivityStatusValue, ActivitySubstatusValue, Start=TimeGenerated, resource, CallerIpAddress
  | join kind=leftanti  ( AzureActivity
  | where OperationNameValue != 'MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE' and OperationNameValue endswith "/DELETE"
  | where ActivityStatusValue == 'Start'
  | project Caller, ResourceProviderValue, resource = tostring(parse_json(Properties).resource), SubscriptionId, ResourceGroup, OperationNameValue, ActivityStatusValue, ActivitySubstatusValue, Start=TimeGenerated) on $left.resource == $right.resource
  | project Caller, ResourceProviderValue, resource, SubscriptionId, ResourceGroup, OperationNameValue, ActivityStatusValue, ActivitySubstatusValue, Start, CallerIpAddress
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = Caller
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = CallerIpAddress
    }
  }
  tactics = ['DefenseEvasion']
  techniques = ['T1562']
  display_name = Azure Diagnostic settings removed from a resource
  description = <<EOT
This query looks for diagnostic settings that are removed from a resource.
This could indicate an attacker or malicious internal trying to evade detection before malicious act is performed.
If the diagnostic settings are being deleted as part of a parent resource deletion, the event is ignores.
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
