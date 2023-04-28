resource "my_alert_rule" "rule_149" {
  name = "Possible Persistance via SDDL Manipulation"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT15M
  query_period = PT15M
  severity = Medium
  query = <<EOF
union(DeviceProcessEvents | where ProcessCommandLine contains "(A;;KA;;;WD)" | extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName),(SecurityEvent | where EventID == "4688" | where CommandLine contains "(A;;KA;;;WD)" | extend AccountCustomEntity = AccountName, HostCustomEntity = Computer)

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
  tactics = ['PrivilegeEscalation']
  techniques = ['T1548', 'T1053']
  display_name = Possible Persistance via SDDL Manipulation
  description = <<EOT
SDDL for Service Control (sc.exe) can be manipulated to allow scheduled tasks to run as system triggering a LPE. 

Reference: https://0xv1n.github.io/posts/scmanager/
https://pentestlab.blog/2023/03/20/persistence-service-control-manager/
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
