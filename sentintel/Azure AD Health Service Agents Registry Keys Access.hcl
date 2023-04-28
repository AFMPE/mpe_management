resource "my_alert_rule" "rule_95" {
  name = "Azure AD Health Service Agents Registry Keys Access"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
// ADHealth Monitoring Agent Registry Key
let aadHealthMonAgentRegKey = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\MicrosoftOnline\\Reporting\\MonitoringAgent";
// Filter out known processes
let aadConnectHealthProcs = dynamic ([
    'Microsoft.Identity.Health.Adfs.DiagnosticsAgent.exe',
    'Microsoft.Identity.Health.Adfs.InsightsService.exe',
    'Microsoft.Identity.Health.Adfs.MonitoringAgent.Startup.exe',
    'Microsoft.Identity.Health.Adfs.PshSurrogate.exe',
    'Microsoft.Identity.Health.Common.Clients.ResourceMonitor.exe',
    'Microsoft.Identity.Health.AadSync.MonitoringAgent.Startup.exe',
    'Microsoft.Identity.AadConnect.Health.AadSync.Host.exe',
    'Microsoft.Azure.ActiveDirectory.Synchronization.Upgrader.exe',
    'miiserver.exe'
]);
(union isfuzzy=true
(
SecurityEvent
| where EventID == '4656'
| where EventData has aadHealthMonAgentRegKey
| extend EventData = parse_xml(EventData).EventData.Data
| mv-expand bagexpansion=array EventData
| evaluate bag_unpack(EventData)
| extend Key = tostring(column_ifexists('@Name', "")), Value = column_ifexists('#text', "")
| evaluate pivot(Key, any(Value), TimeGenerated, Computer, EventID)
| extend ObjectName = column_ifexists("ObjectName", ""),
    ObjectType = column_ifexists("ObjectType", "")
| where ObjectType == 'Key'
| where ObjectName == aadHealthMonAgentRegKey
| extend SubjectUserName = column_ifexists("SubjectUserName", ""),
    SubjectDomainName = column_ifexists("SubjectDomainName", ""),
    ProcessName = column_ifexists("ProcessName", "")
| extend Process = split(ProcessName, '\\', -1)[-1],
    Account = strcat(SubjectDomainName, "\\", SubjectUserName)
| where Process !in (aadConnectHealthProcs)
| summarize StartTime = max(TimeGenerated), EndTime = min(TimeGenerated), count() by EventID, Account, Computer, Process, SubjectUserName, SubjectDomainName, ObjectName, ObjectType, ProcessName
),
  ( WindowsEvent
| where EventID == '4656' and EventData has aadHealthMonAgentRegKey
| extend ObjectType = tostring(EventData.ObjectType)
| where ObjectType == 'Key'
| extend ObjectName = tostring(EventData.ObjectName)
| where ObjectName == aadHealthMonAgentRegKey
| extend ProcessName = tostring(EventData.ProcessName)
| extend Process = tostring(split(ProcessName, '\\')[-1])
| where Process !in (aadConnectHealthProcs)
| extend Account =  strcat(tostring(EventData.SubjectDomainName),"\\", tostring(EventData.SubjectUserName))
| extend SubjectUserName = tostring(EventData.SubjectUserName)
| extend SubjectDomainName = tostring(EventData.SubjectDomainName)
| summarize StartTime = max(TimeGenerated), EndTime = min(TimeGenerated), count() by EventID, Account, Computer, Process, SubjectUserName, SubjectDomainName, ObjectName, ObjectType, ProcessName
),
(
SecurityEvent
| where EventID == '4663'
| where ObjectType == 'Key'
| where ObjectName == aadHealthMonAgentRegKey
| extend Process = tostring(split(ProcessName, '\\', -1)[-1])
| where Process !in (aadConnectHealthProcs)
| summarize StartTime = max(TimeGenerated), EndTime = min(TimeGenerated), count() by EventID, Account, Computer, Process, SubjectUserName, SubjectDomainName, ObjectName, ObjectType, ProcessName
),
( WindowsEvent
| where EventID == '4663' and EventData has aadHealthMonAgentRegKey
| extend ObjectType = tostring(EventData.ObjectType)
| where ObjectType == 'Key'
| extend ObjectName = tostring(EventData.ObjectName)
| where ObjectName == aadHealthMonAgentRegKey
| extend ProcessName = tostring(EventData.ProcessName)
| extend Process = tostring(split(ProcessName, '\\')[-1])
| where Process !in (aadConnectHealthProcs)
| extend Account =  strcat(tostring(EventData.SubjectDomainName),"\\", tostring(EventData.SubjectUserName))
| extend SubjectUserName = tostring(EventData.SubjectUserName)
| extend SubjectDomainName = tostring(EventData.SubjectDomainName)
| summarize StartTime = max(TimeGenerated), EndTime = min(TimeGenerated), count() by EventID, Account, Computer, Process, SubjectUserName, SubjectDomainName, ObjectName, ObjectType, ProcessName
)
)
// You can filter out potential machine accounts
//| where AccountType != 'Machine'
| extend timestamp = StartTime, AccountCustomEntity = Account, HostCustomEntity = Computer
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
  tactics = ['Collection']
  techniques = ['T1005']
  display_name = Azure AD Health Service Agents Registry Keys Access
  description = <<EOT
This detection uses Windows security events to detect suspicious access attempts to the registry key values and sub-keys of Azure AD Health service agents (e.g AD FS).
Information from AD Health service agents can be used to potentially abuse some of the features provided by those services in the cloud (e.g. Federation).
This detection requires an access control entry (ACE) on the system access control list (SACL) of the following securable object: HKLM:\SOFTWARE\Microsoft\ADHealthAgent.
Make sure you set the SACL to propagate to its sub-keys. You can find more information in here https://github.com/OTRF/Set-AuditRule/blob/master/rules/registry/aad_connect_health_service_agent.yml

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
