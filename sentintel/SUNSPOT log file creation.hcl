resource "my_alert_rule" "rule_239" {
  name = "SUNSPOT log file creation"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
union isfuzzy=true
(DeviceFileEvents
| where FolderPath endswith "vmware-vmdmp.log"
| extend HostCustomEntity = DeviceName, timestamp=TimeGenerated),
(WindowsEvent
| where EventID == 4663 and EventData has "vmware-vmdmp.log"
| extend ObjectName = tostring(EventData.ObjectName) 
| where ObjectName endswith "vmware-vmdmp.log"
| extend HostCustomEntity = Computer, timestamp=TimeGenerated),
(SecurityEvent
| where EventID == 4663
| where ObjectName endswith "vmware-vmdmp.log"
| extend HostCustomEntity = Computer, timestamp=TimeGenerated),
(imFileEvent
| where TargetFileName endswith "vmware-vmdmp.log"
| extend HostCustomEntity = DvcHostname, timestamp=TimeGenerated
)
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
  display_name = SUNSPOT log file creation
  description = <<EOT
This query uses Microsoft Defender for Endpoint data and Windows Event Logs to look for IoCs associated with the SUNSPOT malware shared by Crowdstrike.
More details: 
  - https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/ 
  - https://techcommunity.microsoft.com/t5/azure-sentinel/monitoring-your-software-build-process-with-azure-sentinel/ba-p/2140807
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
