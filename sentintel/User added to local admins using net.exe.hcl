resource "my_alert_rule" "rule_214" {
  name = "User added to local admins using net.exe"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
// Query for local admins being added using "net user" command
// In this example we look for use possible uses of uncommon commandline options (/ad instead of /add)
DeviceProcessEvents
// To find executions of a known filename, it is better to filter on the filename (and possibly on folder path).
| where FileName in~ ("net.exe", "net1.exe") and TimeGenerated > ago(1h)
| where ProcessCommandLine has "localgroup administrators"
| where ProcessCommandLine contains "/ad"
| where not (FileName =~ "net1.exe" and InitiatingProcessFileName =~ "net.exe" and replace("net", "net1", InitiatingProcessCommandLine) =~ ProcessCommandLine)
| where not(InitiatingProcessCommandLine has_any ("Scripts\\Startup\\Add_Admin.bat", "KACE"))

EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = DeviceName
    }
  }
  tactics = ['Persistence']
  techniques = ['T1078']
  display_name = User added to local admins using net.exe
  description = <<EOT
Triggers on the use of the "net.exe" executable to add a user to the local administrator group. This alert also triggers on uncommon switches to accomplish this goal for example "/ad" instead of "/add".
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
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
