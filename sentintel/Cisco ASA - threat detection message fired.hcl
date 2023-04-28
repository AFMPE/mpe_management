resource "my_alert_rule" "rule_135" {
  name = "Cisco ASA - threat detection message fired"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
CommonSecurityLog 
| where isempty(CommunicationDirection) 
| where DeviceEventClassID in ("733101","733102","733103","733104","733105")
| extend timestamp = TimeGenerated, IPCustomEntity = SourceIP, HostCustomEntity = DeviceName
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
  tactics = ['Discovery', 'Impact']
  techniques = ['T1046', 'T1498']
  display_name = Cisco ASA - threat detection message fired
  description = <<EOT
Identifies when the Cisco ASA Threat Detection engine fired an alert based on malicious activity occurring on the network inicated by DeviceEventClassID 733101-733105
Resources: https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog/syslogs9.html
Details on how to further troubleshoot/investigate: https://www.cisco.com/c/en/us/support/docs/security/asa-5500-x-series-next-generation-firewalls/113685-asa-threat-detection.html
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
