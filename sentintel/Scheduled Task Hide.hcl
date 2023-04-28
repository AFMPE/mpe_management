resource "my_alert_rule" "rule_363" {
  name = "Scheduled Task Hide"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = High
  query = <<EOF
SecurityEvent
| where EventID == 4657
| extend EventData = parse_xml(EventData).EventData.Data
| mv-expand bagexpansion=array EventData
| evaluate bag_unpack(EventData)
| extend Key = tostring(column_ifexists('@Name', "")), Value = column_ifexists('#text', "")
| evaluate pivot(Key, any(Value), TimeGenerated, TargetAccount, Computer, EventSourceName, Channel, Task, Level, EventID, Activity, TargetLogonId, SourceComputerId, EventOriginId, Type, _ResourceId, TenantId, SourceSystem, ManagementGroupName, IpAddress, Account)
| extend ObjectName = column_ifexists('ObjectName', ""), OperationType = column_ifexists('OperationType', ""), ObjectValueName = column_ifexists('ObjectValueName', "")
| where ObjectName has 'Schedule\\TaskCache\\Tree' and ObjectValueName == "SD" and OperationType == "%%1906"  // %%1906 - Registry value deleted
| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account
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
  tactics = ['DefenseEvasion']
  techniques = ['T1562']
  display_name = Scheduled Task Hide
  description = <<EOT
This query detects attempts by malware to hide the scheduled task by deleting the SD (Security Descriptor) value. Removal of SD value results in the scheduled task disappearing from schtasks /query and Task Scheduler.
 The query requires auditing to be turned on for HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree registry hive as well as audit policy for registry auditing to be turned on.
 Reference: https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/
 Reference: https://4sysops.com/archives/audit-changes-in-the-windows-registry/
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
