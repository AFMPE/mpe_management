resource "my_alert_rule" "rule_283" {
  name = "Azure VM Run Command operations executing a unique powershell script"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let RunCommandData = materialize ( AzureActivity
// Isolate run command actions
| where OperationNameValue == "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION"
// Confirm that the operation impacted a virtual machine
| where Authorization has "virtualMachines"
// Each runcommand operation consists of three events when successful, StartTimeed, Accepted (or Rejected), Successful (or Failed).
| summarize StartTime=min(TimeGenerated), EndTime=max(TimeGenerated), max(CallerIpAddress), make_list(ActivityStatusValue) by CorrelationId, Authorization, Caller
// Limit to Run Command executions that Succeeded
| where list_ActivityStatusValue has "Success"
// Extract data from the Authorization field, allowing us to later extract the Caller (UPN) and CallerIpAddress
| extend Authorization_d = parse_json(Authorization)
| extend Scope = Authorization_d.scope
| extend Scope_s = split(Scope, "/")
| extend Subscription = tostring(Scope_s[2])
| extend VirtualMachineName = tostring(Scope_s[-1])
| project StartTime, EndTime, Subscription, VirtualMachineName, CorrelationId, Caller, CallerIpAddress=max_CallerIpAddress
| join kind=leftouter (
    DeviceFileEvents
    | where InitiatingProcessFileName == "RunCommandExtension.exe"
    | extend VirtualMachineName = tostring(split(DeviceName, ".")[0])
    | project VirtualMachineName, PowershellFileCreatedTimestamp=TimeGenerated, FileName, FileSize, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessFolderPath, InitiatingProcessId
) on VirtualMachineName
// We need to filter by time sadly, this is the only way to link events
| where PowershellFileCreatedTimestamp between (StartTime .. EndTime)
| project StartTime, EndTime, PowershellFileCreatedTimestamp, VirtualMachineName, Caller, CallerIpAddress, FileName, FileSize, InitiatingProcessId, InitiatingProcessAccountDomain, InitiatingProcessFolderPath
| join kind=inner(
    DeviceEvents
    | extend VirtualMachineName = tostring(split(DeviceName, ".")[0])
    | where InitiatingProcessCommandLine has "-File"
    // Extract the script name based on the structure used by the RunCommand extension
    | extend PowershellFileName = extract(@"\-File\s(script[0-9]{1,9}\.ps1)", 1, InitiatingProcessCommandLine)
    // Discard results that didn't successfully extract, these are not run command related
    | where isnotempty(PowershellFileName)
    | extend PSCommand = tostring(parse_json(AdditionalFields).Command)
    // The first execution of PowerShell will be the RunCommand script itself, we can discard this as it will break our hash later
    | where PSCommand != PowershellFileName 
    // Now we normalise the cmdlets, we're aiming to hash them to find scripts using rare combinations
    | extend PSCommand = toupper(PSCommand)
    | order by PSCommand asc
    | summarize PowershellExecStartTime=min(TimeGenerated), PowershellExecEnd=max(TimeGenerated), make_list(PSCommand) by PowershellFileName, InitiatingProcessCommandLine
) on $left.FileName == $right.PowershellFileName
| project StartTime, EndTime, PowershellFileCreatedTimestamp, PowershellExecStartTime, PowershellExecEnd, PowershellFileName, PowershellScriptCommands=list_PSCommand, Caller, CallerIpAddress, InitiatingProcessCommandLine, PowershellFileSize=FileSize, VirtualMachineName
| order by StartTime asc 
// We generate the hash based on the cmdlets called and the size of the powershell script
| extend TempFingerprintString = strcat(PowershellScriptCommands, PowershellFileSize)
| extend ScriptFingerprintHash = hash_sha256(tostring(PowershellScriptCommands)));
let totals = toscalar (RunCommandData
| summarize count());
let hashTotals = RunCommandData
| summarize HashCount=count() by ScriptFingerprintHash;
RunCommandData
| join kind=leftouter (
hashTotals
) on ScriptFingerprintHash
// Calculate prevalence, while we don't need this, it may be useful for responders to know how rare this script is in relation to normal activity
| extend Prevalence = toreal(HashCount) / toreal(totals) * 100
// Where the hash was only ever seen once.
| where HashCount == 1
| extend timestamp = StartTime, IPCustomEntity=CallerIpAddress, AccountCustomEntity=Caller, HostCustomEntity=VirtualMachineName
| project timestamp, StartTime, EndTime, PowershellFileName, VirtualMachineName, Caller, CallerIpAddress, PowershellScriptCommands, PowershellFileSize, ScriptFingerprintHash, Prevalence, IPCustomEntity, AccountCustomEntity, HostCustomEntity
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = HostCustomEntity
    }
  }
  tactics = ['LateralMovement', 'Execution']
  techniques = ['T1570', 'T1059']
  display_name = Azure VM Run Command operations executing a unique PowerShell script
  description = <<EOT
Identifies when Azure Run command is used to execute a PowerShell script on a VM that is unique.
The uniqueness of the PowerShell script is determined by taking a combined hash of the cmdLets it imports
and the file size of the PowerShell script. Alerts from this detection indicate a unique PowerShell was executed
in your environment.
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
