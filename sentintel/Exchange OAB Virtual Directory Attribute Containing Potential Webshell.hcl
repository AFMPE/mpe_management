resource "my_alert_rule" "rule_146" {
  name = "Exchange OAB Virtual Directory Attribute Containing Potential Webshell"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = High
  query = <<EOF
SecurityEvent
// Look for specific Directory Service Changes and parse data
| where EventID == 5136
| extend EventData = parse_xml(EventData).EventData.Data
| mv-expand bagexpansion = array EventData
| evaluate bag_unpack(EventData)
| extend Key = tostring(column_ifexists('@Name', "")), Value = column_ifexists('#text', "")
| evaluate pivot(Key, any(Value),TimeGenerated, EventID, Computer, Account, AccountType, EventSourceName, Activity, SubjectAccount)
// Where changes relate to Exchange OAB
| extend ObjectClass = column_ifexists("ObjectClass", "")
| where ObjectClass =~ "msExchOABVirtualDirectory"
// Look for InternalHostName or ExternalHostName properties being changed
| extend AttributeLDAPDisplayName = column_ifexists("AttributeLDAPDisplayName", "")
| where AttributeLDAPDisplayName in ("msExchExternalHostName", "msExchInternalHostName")
// Look for suspected webshell activity
| extend AttributeValue = column_ifexists("AttributeValue", "")
| where AttributeValue has "script"
| project-rename LastSeen = TimeGenerated
| extend ObjectDN = column_ifexists("ObjectDN", "")
| project-reorder LastSeen, Computer, Account, ObjectDN, AttributeLDAPDisplayName, AttributeValue
| extend timestamp = LastSeen, AccountCustomEntity = Account, HostCustomEntity = Computer
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
  tactics = ['InitialAccess']
  techniques = ['T1190']
  display_name = Exchange OAB Virtual Directory Attribute Containing Potential Webshell
  description = <<EOT
This query uses Windows Event ID 5136 in order to detect potential webshell deployment by exploitation of CVE-2021-27065.
This query looks for changes to the InternalHostName or ExternalHostName properties of Exchange OAB Virtual Directory objects in AD Directory Services
where the new objects contain potential webshell objects. Ref: https://aka.ms/ExchangeVulns
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
