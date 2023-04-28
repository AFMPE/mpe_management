resource "my_alert_rule" "rule_110" {
  name = "Potential Modification of Accessibility Binaries"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Low
  query = <<EOF
let SE =
(SecurityEvent
| where EventID == 4688 and ParentProcessName has "winlogon.exe" and Process in ("atbroker.exe" ,"displayswitch.exe" ,"magnify.exe" ,"narrator.exe" ,"osk.exe" ,"sethc.exe" ,"utilman.exe")
| where not(CommandLine matches regex @"(?:sethc.exe)\s\d{1,3}")
| extend AccountCustomEntity = Account, HostCustomEntity = Computer
);
let DPE =
(DeviceProcessEvents
| where ((InitiatingProcessParentFileName has "winlogon.exe" and InitiatingProcessFileName in ("atbroker.exe" ,"displayswitch.exe" ,"magnify.exe" ,"narrator.exe" ,"osk.exe" ,"sethc.exe" ,"utilman.exe"))) or (InitiatingProcessFileName has "winlogon.exe" and FileName in ("atbroker.exe" ,"displayswitch.exe" ,"magnify.exe" ,"narrator.exe" ,"osk.exe" ,"sethc.exe" ,"utilman.exe"))
| where not(ProcessCommandLine matches regex @"(?:sethc.exe)\s\d{1,3}" or ProcessCommandLine matches regex @'(?:\"EaseOfAccessDialog.exe\")\s\d{1,3}')
| extend AccountCustomEntity = AccountUpn, HostCustomEntity = DeviceName)
;
SE
|union DPE
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
  tactics = ['Persistence', 'PrivilegeEscalation']
  techniques = ['T1546']
  display_name = Potential Modification of Accessibility Binaries
  description = <<EOT
'Windows contains accessibility features that may be launched with a key combination before a user has logged in. An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system.'

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
