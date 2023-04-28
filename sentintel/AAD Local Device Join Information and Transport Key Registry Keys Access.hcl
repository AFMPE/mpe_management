resource "my_alert_rule" "rule_289" {
  name = "AAD Local Device Join Information and Transport Key Registry Keys Access"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
// AADJoined or Register Device Registry Keys
let aadJoinRoot = "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\CloudDomainJoin\\JoinInfo\\";
let aadRegisteredRoot = "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\WorkplaceJoin";
// Transport Key Registry Key
let keyTransportKey = "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Cryptography\\Ngc\\KeyTransportKey\\";
(union isfuzzy=true
(
// Access to Object Requested
SecurityEvent
| where EventID == '4656'
| where EventData contains aadJoinRoot or EventData contains aadRegisteredRoot
| extend EventData = parse_xml(EventData).EventData.Data
| mv-expand bagexpansion=array EventData
| evaluate bag_unpack(EventData)
| extend Key = tostring(column_ifexists('@Name', "")), Value = column_ifexists('#text', "")
| evaluate pivot(Key, any(Value), TimeGenerated, Computer, EventID)
| where ObjectType == 'Key'
| where ObjectName startswith aadJoinRoot and SubjectLogonId != '0x3e7' //Local System
| extend ProcessId = column_ifexists("ProcessId", ""), Process = split(ProcessName, '\\', -1)[-1],Account = strcat(SubjectDomainName, "\\", SubjectUserName)
| join kind=innerunique (
    SecurityEvent
    | where EventID == '4656'
    | where EventData contains keyTransportKey
    | extend EventData = parse_xml(EventData).EventData.Data
    | mv-expand bagexpansion=array EventData
    | evaluate bag_unpack(EventData)
    | extend Key = tostring(column_ifexists('@Name', "")), Value = column_ifexists('#text', "")
    | evaluate pivot(Key, any(Value), TimeGenerated, Computer, EventID)
    | extend ObjectName = column_ifexists("ObjectName", ""),ObjectType = column_ifexists("ObjectType", "")
    | where ObjectType == 'Key'
    | where ObjectName startswith keyTransportKey and SubjectLogonId != '0x3e7' //Local System
    | extend ProcessId = column_ifexists("ProcessId", ""), Process = split(ProcessName, '\\', -1)[-1],Account = strcat(SubjectDomainName, "\\", SubjectUserName)
) on $left.Computer == $right.Computer and $left.SubjectLogonId == $right.SubjectLogonId and $left.ProcessId == $right.ProcessId
| project TimeGenerated, Computer, Account, SubjectDomainName, SubjectUserName, SubjectLogonId, ObjectName, tostring(Process), ProcessName, ProcessId, EventID
),
// Accessing Object
(
SecurityEvent
| where EventID == '4663'
| where ObjectType == 'Key'
| where (ObjectName startswith aadJoinRoot or ObjectName contains aadRegisteredRoot) and SubjectLogonId != '0x3e7' //Local System
| extend Account = SubjectAccount
| join kind=innerunique (
    SecurityEvent
    | where EventID == '4663'
    | where ObjectType == 'Key'
    | where ObjectName contains keyTransportKey and SubjectLogonId != '0x3e7' //Local System
    | extend Account = SubjectAccount
) on $left.Computer == $right.Computer and $left.SubjectLogonId == $right.SubjectLogonId and $left.ProcessId == $right.ProcessId
| project TimeGenerated, Computer, Account, SubjectDomainName, SubjectUserName, SubjectLogonId, ObjectName, Process, ProcessName, ProcessId, EventID
)
)
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
  }
  tactics = ['Discovery']
  techniques = ['T1012']
  display_name = AAD Local Device Join Information and Transport Key Registry Keys Access
  description = <<EOT
This detection uses Windows security events to detect suspicious access attempts by the same process
 to registry keys that provide information about an AAD joined or registered devices and Transport keys (tkpub / tkpriv).
 This information can be used to export the Device Certificate (dkpub / dkpriv) and Transport key (tkpub/tkpriv).
 These set of keys can be used to impersonate existing Azure AD joined devices.
 This detection requires an access control entry (ACE) on the system access control list (SACL) of the following securable objects:
 HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin (AAD joined devices)
 HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin (AAD registered devices)
 HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc\KeyTransportKey (Transport Key)
 Make sure you set the SACL to propagate to its sub-keys. You can find more information in here https://github.com/OTRF/Set-AuditRule/blob/master/rules/registry/aad_connect_health_service_agent.yml
 Reference: https://o365blog.com/post/deviceidentity/
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
