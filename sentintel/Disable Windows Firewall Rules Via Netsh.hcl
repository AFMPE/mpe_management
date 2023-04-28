resource "my_alert_rule" "rule_85" {
  name = "Disable Windows Firewall Rules Via Netsh"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = High
  query = <<EOF
let SELogs = (SecurityEvent
    | where Channel == "Security"
    | where EventID == "4688"
    | where (CommandLine contains "netsh advfirewall set" and CommandLine contains "off") 
        or (CommandLine contains "Set-NetFirewallProfile" and CommandLine contains "-Enabled False")
    | extend AccountCustomEntity = Account 
    | extend HostCustomEntity = Computer);
let DPELogs = (DeviceProcessEvents
| where ProcessCommandLine has_all ("netsh", "advfirewall", "set", "off") or ProcessCommandLine has_all ("Set-NetFirewallProfile","-Enabled False")
| extend AccountCustomEntity = AccountName 
| extend HostCustomEntity = DeviceName
);
SELogs
| union DPELogs
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
  tactics = ['DefenseEvasion']
  techniques = ['T1562']
  display_name = Disable Windows Firewall Rules Via Netsh
  description = <<EOT
'Identifies use of the netsh.exe to disable or weaken the local firewall. Attackers will use this command line tool to disable the firewall during troubleshooting or to enable network mobility.'

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
  suppression_duration = PT5M
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
