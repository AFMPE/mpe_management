resource "my_alert_rule" "rule_192" {
  name = "Unusual identity creation using exchange powershell"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT12H
  query_period = PT12H
  severity = High
  query = <<EOF
(union isfuzzy=true
(SecurityEvent
| where EventID==4688
| where CommandLine has_any ("New-Mailbox","Update-RoleGroupMember") and CommandLine has "HealthMailbox55x2yq"
| project TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account, AccountDomain, ProcessName, ProcessNameFullPath = NewProcessName, EventID, Activity, CommandLine, EventSourceName, Type
),
(DeviceProcessEvents
| where ProcessCommandLine has_any ("New-Mailbox","Update-RoleGroupMember") and ProcessCommandLine has "HealthMailbox55x2yq"
| extend timestamp = TimeGenerated, AccountCustomEntity =  InitiatingProcessAccountName, HostCustomEntity = DeviceName
)
)
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
  }
  tactics = ['Persistence']
  techniques = ['T1136']
  display_name = Unusual identity creation using exchange powershell
  description = <<EOT
 The query below identifies creation of unusual identity by the Europium actor to mimic Microsoft Exchange Health Manager Service account using Exchange PowerShell commands
  Reference: https://www.microsoft.com/security/blog/2022/09/08/microsoft-investigates-iranian-attacks-against-the-albanian-government/
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
