resource "my_alert_rule" "rule_202" {
  name = "Dev-0270 Malicious Powershell usage"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT6H
  query_period = PT6H
  severity = High
  query = <<EOF
(union isfuzzy=true
(SecurityEvent
| where EventID==4688
| extend FileName=tostring(split(NewProcessName, @'')[(-1)]),  ProcessCommandLine = CommandLine, InitiatingProcessFileName=ParentProcessName
| where (FileName =~ "powershell.exe" and ProcessCommandLine has_all("try", "Add-MpPreference", "-ExclusionPath", "ProgramData", "catch")) or (FileName =~ 'powershell.exe' and ProcessCommandLine has_all('Add-PSSnapin', 'Get-Recipient', '-ExpandProperty', 'EmailAddresses', 'SmtpAddress', '-hidetableheaders') )
| project TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account, AccountDomain, ProcessName, ProcessNameFullPath = NewProcessName, EventID, Activity, CommandLine, EventSourceName, Type
),
(DeviceProcessEvents 
| where (FileName =~ "powershell.exe" and ((ProcessCommandLine has_all("try", "Add-MpPreference", "-ExclusionPath", "ProgramData", "catch"))  or (ProcessCommandLine has_all('Add-PSSnapin', 'Get-Recipient', '-ExpandProperty', 'EmailAddresses', 'SmtpAddress', '-hidetableheaders'))))
or ( InitiatingProcessFileName =~ 'powershell.exe' and (((InitiatingProcessCommandLine has_all('$file=', 'dllhost.exe', 'Invoke-WebRequest', '-OutFile')) or ((InitiatingProcessCommandLine has_all('$admins=', 'System.Security.Principal.SecurityIdentifier', 'Translate', '-split', 'localgroup', '/add', '$rdp='))))))
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
  tactics = ['Exfiltration', 'DefenseEvasion']
  techniques = ['T1048', 'T1562']
  display_name = Dev-0270 Malicious Powershell usage
  description = <<EOT
DEV-0270 heavily uses powershell to achieve their objective at various stages of their attack. To locate powershell related activity tied to the actor, Microsoft Sentinel customers can run the following query.
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
