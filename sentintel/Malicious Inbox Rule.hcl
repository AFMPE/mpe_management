resource "my_alert_rule" "rule_63" {
  name = "Malicious Inbox Rule"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let Keywords = dynamic(["helpdesk", " alert", " suspicious", "fake", "malicious", "phishing", "spam", "do not click", "do not open", "hijacked", "Fatal"]);
OfficeActivity
| where Operation =~ "New-InboxRule"
| where Parameters has "Deleted Items" or Parameters has "Junk Email"  or Parameters has "DeleteMessage"
| extend Events=todynamic(Parameters)
| parse Events  with * "SubjectContainsWords" SubjectContainsWords '}'*
| parse Events  with * "BodyContainsWords" BodyContainsWords '}'*
| parse Events  with * "SubjectOrBodyContainsWords" SubjectOrBodyContainsWords '}'*
| where SubjectContainsWords has_any (Keywords)
 or BodyContainsWords has_any (Keywords)
 or SubjectOrBodyContainsWords has_any (Keywords)
| extend ClientIPAddress = case( ClientIP has ".", tostring(split(ClientIP,":")[0]), ClientIP has "[", tostring(trim_start(@'[[]',tostring(split(ClientIP,"]")[0]))), ClientIP )
| extend Keyword = iff(isnotempty(SubjectContainsWords), SubjectContainsWords, (iff(isnotempty(BodyContainsWords),BodyContainsWords,SubjectOrBodyContainsWords )))
| extend RuleDetail = case(OfficeObjectId contains '/' , tostring(split(OfficeObjectId, '/')[-1]) , tostring(split(OfficeObjectId, '\\')[-1]))
| summarize count(), StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by  Operation, UserId, ClientIPAddress, ResultStatus, Keyword, OriginatingServer, OfficeObjectId, RuleDetail
| extend timestamp = StartTimeUtc,  IPCustomEntity = ClientIPAddress, AccountCustomEntity = UserId , HostCustomEntity =  OriginatingServer
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['Persistence', 'DefenseEvasion']
  techniques = ['T1078', 'T1098']
  display_name = Malicious Inbox Rule
  description = <<EOT
Often times after the initial compromise the attackers create inbox rules to delete emails that contain certain keywords. 
 This is done so as to limit ability to warn compromised users that they've been compromised. Below is a sample query that tries to detect this.
Reference: https://www.reddit.com/r/sysadmin/comments/7kyp0a/recent_phishing_attempts_my_experience_and_what/
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
