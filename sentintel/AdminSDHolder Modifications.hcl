resource "my_alert_rule" "rule_27" {
  name = "AdminSDHolder Modifications"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = High
  query = <<EOF
SecurityEvent
| where EventID == 5136 and EventData contains "<Data Name=\"ObjectDN\">CN=AdminSDHolder,CN=System"
| parse EventData with * 'ObjectDN">' ObjectDN "<" *
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by Computer, SubjectAccount, SubjectUserSid, SubjectLogonId, ObjectDN
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = SubjectAccount
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = Computer
    }
  }
  tactics = ['Persistence']
  techniques = ['T1078']
  display_name = AdminSDHolder Modifications
  description = <<EOT
This query detects modification in the AdminSDHolder  in the Active Directory which could indicate an attempt for persistence. 
AdminSDHolder Modification is a persistence technique in which an attacker abuses the SDProp process in Active Directory to establish a persistent backdoor to Active Directory.
This query searches for the event id 5136 where the Object DN is AdminSDHolder.
Ref: https://attack.stealthbits.com/adminsdholder-modification-ad-persistence
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
