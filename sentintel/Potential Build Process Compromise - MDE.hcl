resource "my_alert_rule" "rule_117" {
  name = "Potential Build Process Compromise - MDE"
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
let allow_list = dynamic([]);
DeviceProcessEvents
| where TimeGenerated > ago(timeframe)
// Look for build process starts
| where FileName has_any (build_processes)
| summarize by BuildParentProcess=InitiatingProcessFileName, BuildProcess=FileName, BuildAccount = AccountName, DeviceName, BuildCommand=ProcessCommandLine, timekey= bin(TimeGenerated, time_window), BuildProcessTime=TimeGenerated
| join kind=inner(
DeviceFileEvents
| where TimeGenerated > ago(timeframe)
| where InitiatingProcessFileName !in (allow_list)
| where ActionType == "FileCreated"  or ActionType == "FileModified"
// Look for code files, edit this to include file extensions used in build.
| where FileName endswith ".cs" or FileName endswith ".cpp"
| summarize by FileEditParentProcess=InitiatingProcessParentFileName, FileEditAccount = InitiatingProcessAccountName, DeviceName, FileEdited=FileName, FileEditProcess=InitiatingProcessFileName, timekey= bin(TimeGenerated, time_window), FileEditTime=TimeGenerated)
// join where build processes and file modifications seen at same time on same host
on timekey, DeviceName
// Limit to only where the file edit happens after the build process starts
| where BuildProcessTime <= FileEditTime
| summarize make_set(FileEdited), make_set(FileEditProcess), make_set(FileEditAccount) by timekey, DeviceName, BuildParentProcess, BuildProcess
| extend HostCustomEntity=DeviceName, timestamp=timekey
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
  display_name = Potential Build Process Compromise - MDE
  description = <<EOT
The query looks for source code files being modified immediately after a build process is started. The purpose of this is to look for malicious code injection during the build process. This query uses Microsoft Defender for Endpoint telemetry.
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
