resource "my_alert_rule" "rule_366" {
  name = "ChromeLoader IOC Detected"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT15M
  query_period = PT15M
  severity = Medium
  query = <<EOF
union(DeviceProcessEvents 
| where (InitiatingProcessFileName has "Powershell" and ProcessCommandLine has_all ("chrome.exe", "load-extension", "AppData\\Local")) 
  or (InitiatingProcessFileName has_any ("sh", "bash") and ProcessCommandLine has_all ("/tmp/", "load-extension", "chrome"))
| project TimeGenerated, AccountCustomEntity = AccountName, HostCustomEntity = DeviceName, CommandLine = ProcessCommandLine
), (SecurityEvent 
| where ParentProcessName has "Powershell" and CommandLine has_all ("chrome.exe", "load-extension", "AppData\\Local")
| project TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, CommandLine
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
    entity_type = Process
    field_mappings {
      identifier = CommandLine
      column_name = CommandLine
    }
  }
  tactics = ['Execution']
  techniques = ['T1204']
  display_name = ChromeLoader IOC Detected
  description = <<EOT
This rule detects IOC's of ChromeLoader as noted in https://redcanary.com/blog/chromeloader/
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
