resource "my_alert_rule" "rule_159" {
  name = "Rare and potentially high-risk Office operations"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
OfficeActivity
| where Operation in~ ( "Add-MailboxPermission", "Add-MailboxFolderPermission", "Set-Mailbox", "New-ManagementRoleAssignment", "New-InboxRule", "Set-InboxRule", "Set-TransportRule")
and not(UserId has_any ('NT AUTHORITY\\SYSTEM (Microsoft.Exchange.ServiceHost)', 'NT AUTHORITY\\SYSTEM (w3wp)', 'devilfish-applicationaccount') and Operation in~ ( "Add-MailboxPermission", "Set-Mailbox"))
| extend ClientIPOnly = tostring(extract_all(@'\[?(::ffff:)?(?P<IPAddress>(\d+\.\d+\.\d+\.\d+)|[^\]]+)\]?', dynamic(["IPAddress"]), ClientIP)[0][0])
| extend timestamp = TimeGenerated, AccountCustomEntity = UserId, IPCustomEntity = ClientIPOnly
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
  tactics = ['Persistence', 'Collection']
  techniques = ['T1098', 'T1114']
  display_name = Rare and potentially high-risk Office operations
  description = <<EOT
Identifies Office operations that are typically rare and can provide capabilities useful to attackers.
EOT
  enabled = False
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
