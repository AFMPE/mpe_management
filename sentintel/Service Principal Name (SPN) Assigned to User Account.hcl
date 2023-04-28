resource "my_alert_rule" "rule_226" {
  name = "Service Principal Name (SPN) Assigned to User Account"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
SecurityEvent
| where EventID == 5136 
| parse EventData with * 'AttributeLDAPDisplayName">' AttributeLDAPDisplayName "<" *
| parse EventData with * 'ObjectClass">' ObjectClass "<" *
| where AttributeLDAPDisplayName == "servicePrincipalName" and  ObjectClass == "user"
| parse EventData with * 'ObjectDN">' ObjectDN "<" *
| parse EventData with * 'AttributeValue">' AttributeValue "<" *
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by Computer, SubjectAccount, ObjectDN, AttributeValue
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
  tactics = ['PrivilegeEscalation']
  techniques = ['T1134']
  display_name = Service Principal Name (SPN) Assigned to User Account
  description = <<EOT
This query identifies whether a Active Directory user object was assigned a service principal name which could indicate that an adversary is preparing for performing Kerberoasting. 
This query checks for event id 5136 that the Object Class field is "user" and the LDAP Display Name is "servicePrincipalName".
Ref: https://thevivi.net/assets/docs/2019/theVIVI-AD-Security-Workshop_AfricaHackon2019.pdf
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
