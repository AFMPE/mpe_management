resource "my_alert_rule" "rule_221" {
  name = "AzureTokenReq Not Via Chrome"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
let SE = (SecurityEvent
| where NewProcessName contains "BrowserCore.exe" and ParentProcessName !contains "cmd.exe" 
or NewProcessName contains "cmd.exe" and ParentProcessName contains "chrome.exe" and CommandLine !contains "\\\\.\\pipe\\"
| where not(ParentProcessName has_any ("Microsoft\\Teams\\current\\Teams.exe"))
| where CommandLine <> ""
| sort by TimeGenerated
| project TimeGenerated, Computer, Account, CommandLine);
let DfE = (DeviceProcessEvents
| where FileName has "BrowserCore.exe" and InitiatingProcessFileName !has "cmd.exe"
  or  InitiatingProcessFileName has "chrome.exe" and FileName has "cmd.exe" and ProcessCommandLine !contains "\\\\.\\pipe\\"
| where InitiatingProcessFileName !has "Teams.exe"
| project TimeGenerated, Computer = DeviceName, Account = AccountName, CommandLine = ProcessCommandLine);
SE
| union DfE
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = Account
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = Computer
    }
    entity_type = Process
    field_mappings {
      identifier = CommandLine
      column_name = CommandLine
    }
  }
  tactics = ['DefenseEvasion']
  techniques = ['T1036']
  display_name = AzureTokenReq Not Via Chrome
  description = <<EOT
'Technique explained here => https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/'

EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
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
