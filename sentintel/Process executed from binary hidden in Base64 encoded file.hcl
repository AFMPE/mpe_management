resource "my_alert_rule" "rule_326" {
  name = "Process executed from binary hidden in Base64 encoded file"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let ProcessCreationEvents=() {
let processEvents=(union isfuzzy=true
(SecurityEvent
| where EventID==4688
| where isnotempty(CommandLine)
| project TimeGenerated, Computer, Account = SubjectUserName, AccountDomain = SubjectDomainName, FileName = Process, CommandLine, ParentProcessName
),
(WindowsEvent
| where EventID==4688
| where EventData has_any (".decode('base64')", "base64 --decode", ".decode64(" )
| extend CommandLine = tostring(EventData.CommandLine)
| where isnotempty(CommandLine)
| extend SubjectUserName = tostring(EventData.SubjectUserName)
| extend SubjectDomainName = tostring(EventData.SubjectDomainName)
| extend NewProcessName = tostring(EventData.NewProcessName)
| extend FileName=tostring(split(NewProcessName, '\\')[-1])
| extend ParentProcessName = tostring(EventData.ParentProcessName)
| project TimeGenerated, Computer, Account = SubjectUserName, AccountDomain = SubjectDomainName, CommandLine, ParentProcessName
));
processEvents;
};
ProcessCreationEvents 
| where CommandLine contains ".decode('base64')"
        or CommandLine contains "base64 --decode"
        or CommandLine contains ".decode64(" 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), CountToday = count() by Computer, Account, AccountDomain, FileName, CommandLine, ParentProcessName 
| extend timestamp = StartTimeUtc, AccountCustomEntity = Account, HostCustomEntity = Computer
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
  tactics = ['Execution', 'DefenseEvasion']
  techniques = ['T1059', 'T1027', 'T1140']
  display_name = Process executed from binary hidden in Base64 encoded file
  description = <<EOT
Encoding malicious software is a technique used to obfuscate files from detection. 
The first CommandLine component is looking for Python decoding base64. 
The second CommandLine component is looking for Bash/sh command line base64 decoding.
The third one is looking for Ruby decoding base64.
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
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
