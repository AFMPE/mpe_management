resource "my_alert_rule" "rule_17" {
  name = "Potential Build Process Compromise"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
// How far back to look for events from
let timeframe = 1d;
// How close together build events and file modifications should occur to alert (make this smaller to reduce FPs)
let time_window = 5m;
// Edit this to include build processes used
let build_processes = dynamic(["MSBuild.exe", "dotnet.exe", "VBCSCompiler.exe"]);
// Include any processes that you want to allow to edit files during/around the build process
let allow_list = dynamic([""]);
(union isfuzzy=true
(SecurityEvent
| where TimeGenerated > ago(timeframe)
// Look for build process starts
| where EventID == 4688
| where Process has_any (build_processes)
| summarize by BuildParentProcess=ParentProcessName, BuildProcess=Process, BuildAccount = Account, Computer, BuildCommand=CommandLine, timekey= bin(TimeGenerated, time_window), BuildProcessTime=TimeGenerated
| join kind=inner(
SecurityEvent
| where TimeGenerated > ago(timeframe)
// Look for file modifications to code file
| where EventID == 4663
| where Process !in (allow_list)
// Look for code files, edit this to include file extensions used in build.
| where ObjectName endswith ".cs" or ObjectName endswith ".cpp"
// 0x6 and 0x4 for file append, 0x100 for file replacements
| where AccessMask == "0x6"  or AccessMask == "0x4" or AccessMask == "0X100"
| summarize by FileEditParentProcess=ParentProcessName, FileEditAccount = Account, Computer, FileEdited=ObjectName, FileEditProcess=ProcessName, timekey= bin(TimeGenerated, time_window), FileEditTime=TimeGenerated)
// join where build processes and file modifications seen at same time on same host
on timekey, Computer
// Limit to only where the file edit happens after the build process starts
| where BuildProcessTime <= FileEditTime
| summarize make_set(FileEdited), make_set(FileEditProcess), make_set(FileEditAccount) by timekey, Computer, BuildParentProcess, BuildProcess
| extend HostCustomEntity=Computer, timestamp=timekey
),
(WindowsEvent
| where TimeGenerated > ago(timeframe)
// Look for build process starts
| where EventID == 4688 and EventData has_any (build_processes)
| extend NewProcessName = tostring(EventData.NewProcessName)
| extend Process=tostring(split(NewProcessName, '\\')[-1])
| where Process has_any (build_processes)
| extend ParentProcessName = tostring(EventData.ParentProcessName)
| extend Account =  strcat(tostring(EventData.SubjectDomainName),"\\", tostring(EventData.SubjectUserName))
| extend CommandLine = tostring(EventData.CommandLine) 
| summarize by BuildParentProcess=ParentProcessName, BuildProcess=Process, BuildAccount = Account, Computer, BuildCommand=CommandLine, timekey= bin(TimeGenerated, time_window), BuildProcessTime=TimeGenerated
| join kind=inner(
WindowsEvent
| where TimeGenerated > ago(timeframe)
// Look for file modifications to code file
| where EventID == 4663 and EventData has_any ("0x6", "0x4", "0X100") and EventData has_any (".cs", ".cpp")
| extend NewProcessName = tostring(EventData.NewProcessName)
| extend Process=tostring(split(NewProcessName, '\\')[-1])
| where Process !in (allow_list)
// Look for code files, edit this to include file extensions used in build.
| extend ObjectName = tostring(EventData.ObjectName)
| where ObjectName endswith ".cs" or ObjectName endswith ".cpp"
// 0x6 and 0x4 for file append, 0x100 for file replacements
| extend AccessMask = tostring(EventData.AccessMask)  
| where AccessMask == "0x6"  or AccessMask == "0x4" or AccessMask == "0X100"
| extend ParentProcessName = tostring(EventData.ParentProcessName)
| extend Account =  strcat(tostring(EventData.SubjectDomainName),"\\", tostring(EventData.SubjectUserName))
| extend ProcessName = tostring(EventData.ProcessName)
| summarize by FileEditParentProcess=ParentProcessName, FileEditAccount = Account, Computer, FileEdited=ObjectName, FileEditProcess=ProcessName, timekey= bin(TimeGenerated, time_window), FileEditTime=TimeGenerated)
// join where build processes and file modifications seen at same time on same host
on timekey, Computer
// Limit to only where the file edit happens after the build process starts
| where BuildProcessTime <= FileEditTime
| summarize make_set(FileEdited), make_set(FileEditProcess), make_set(FileEditAccount) by timekey, Computer, BuildParentProcess, BuildProcess
| extend HostCustomEntity=Computer, timestamp=timekey
))
EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
  }
  tactics = ['Persistence']
  techniques = ['T1554']
  display_name = Potential Build Process Compromise
  description = <<EOT
The query looks for source code files being modified immediately after a build process is started. The purpose of this is to look for malicious code injection during the build process.
More details: https://techcommunity.microsoft.com/t5/azure-sentinel/monitoring-the-software-supply-chain-with-azure-sentinel/ba-p/2176463
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