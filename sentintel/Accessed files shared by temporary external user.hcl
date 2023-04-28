resource "my_alert_rule" "rule_168" {
  name = "Accessed files shared by temporary external user"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Low
  query = <<EOF
let fileAccessThrehold = 10;
OfficeActivity
 | where OfficeWorkload =~ "MicrosoftTeams"
 | where Operation =~ "MemberAdded"
 | extend UPN = tostring(parse_json(Members)[0].UPN)
 | where UPN contains ("#EXT#")
 | project TimeAdded=TimeGenerated, Operation, UPN, UserWhoAdded = UserId, TeamName
 | join kind = inner(
                       OfficeActivity
                       | where OfficeWorkload =~ "MicrosoftTeams"
                       | where Operation =~ "MemberRemoved"
                       | extend UPN = tostring(parse_json(Members)[0].UPN)
                       | where UPN contains ("#EXT#")
                       | project TimeDeleted=TimeGenerated, Operation, UPN, UserWhoDeleted = UserId, TeamName
                     ) on UPN
 | where TimeDeleted > TimeAdded
 | join kind=inner 
                   (
                   OfficeActivity
                   | where RecordType == "SharePointFileOperation"
                   | where SourceRelativeUrl has "Microsoft Teams Chat Files"
                   | where Operation == "FileUploaded"
                   | join kind = inner 
                                       (
                                       OfficeActivity
                                       | where RecordType == "SharePointFileOperation"
                                       | where Operation  == "FileAccessed"
                                       | where SourceRelativeUrl has "Microsoft Teams Chat Files"
                                       | summarize FileAccessCount = count() by OfficeObjectId
                                       | where FileAccessCount > fileAccessThrehold
                                       ) on $left.OfficeObjectId == $right.OfficeObjectId
                   )on $left.UPN == $right.UserId
 | extend timestamp=TimeGenerated, AccountCustomEntity = UserWhoAdded
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
  }
  tactics = ['InitialAccess']
  techniques = ['T1566']
  display_name = Accessed files shared by temporary external user
  description = <<EOT
This detection identifies an external user is added to a Team or Teams chat
and shares a files which is accessed by many users (>10) and the users is removed within short period of time. This might be
an indicator of suspicious activity.
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
