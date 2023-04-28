resource "my_alert_rule" "rule_191" {
  name = "Solorigate Defender Detections"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = High
  query = <<EOF
DeviceInfo
| extend DeviceName = tolower(DeviceName)
| join (SecurityAlert
| where ProviderName =~ "MDATP"
| extend ThreatName = tostring(parse_json(ExtendedProperties).ThreatName)
| where ThreatName has "Solorigate"
| extend HostCustomEntity = tolower(CompromisedEntity)
) on $left.DeviceName == $right.HostCustomEntity
| project TimeGenerated, DisplayName, ThreatName, CompromisedEntity, PublicIP, MachineGroup, AlertSeverity, Description, LoggedOnUsers, DeviceId, TenantId, HostCustomEntity
| extend timestamp = TimeGenerated, IPCustomEntity = PublicIP
EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['InitialAccess']
  techniques = ['T1195']
  display_name = Solorigate Defender Detections
  description = <<EOT
Surfaces any Defender Alert for Solorigate Events. In Azure Sentinel the SecurityAlerts table includes only the Device Name of the affected device, this query joins the DeviceInfo table to clearly connect other information such as 
 Device group, ip, logged on users etc. This way, the Sentinel user can have all the pertinent device info in one view for all the the Solarigate Defender alerts.
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
