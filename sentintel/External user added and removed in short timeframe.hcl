resource "my_alert_rule" "rule_206" {
  name = "External user added and removed in short timeframe"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Low
  query = <<EOF
let TeamsAddDel = (Op:string){
OfficeActivity
| where OfficeWorkload =~ "MicrosoftTeams"
| where Operation == Op
| where Members has ("#EXT#")
| mv-expand Members
| extend UPN = tostring(Members.UPN)
| where UPN has ("#EXT#")
| project TimeGenerated, Operation, UPN, UserId, TeamName
};
let TeamsAdd = TeamsAddDel("MemberAdded")
| project TimeAdded=TimeGenerated, Operation, UPN, UserWhoAdded = UserId, TeamName;
let TeamsDel = TeamsAddDel("MemberRemoved")
| project TimeDeleted=TimeGenerated, Operation, UPN, UserWhoDeleted = UserId, TeamName;
TeamsAdd
| join kind=inner (TeamsDel) on UPN
| where TimeDeleted > TimeAdded
| project TimeAdded, TimeDeleted, UPN, UserWhoAdded, UserWhoDeleted, TeamName
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = UPN
    }
  }
  tactics = ['Persistence']
  techniques = ['T1136']
  display_name = External user added and removed in short timeframe
  description = <<EOT
This detection flags the occurances of external user accounts that are added to a Team and then removed within
one hour.
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
