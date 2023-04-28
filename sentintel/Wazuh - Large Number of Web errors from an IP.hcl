resource "my_alert_rule" "rule_210" {
  name = "Wazuh - Large Number of Web errors from an IP"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
CommonSecurityLog
| where DeviceProduct =~ "Wazuh"
| where Activity has "Web server 400 error code."
| where Message has "403"
| extend HostName=substring(split(DeviceCustomString1,")")[0],1)
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), NumberOfErrors = dcount(SourceIP) by HostName, SourceIP
| where NumberOfErrors > 400
| sort by NumberOfErrors desc
| extend timestamp = StartTime, HostCustomEntity = HostName, IPCustomEntity = SourceIP
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
  tactics = ['Persistence']
  techniques = ['T1133']
  display_name = Wazuh - Large Number of Web errors from an IP
  description = <<EOT
Identifies instances where Wazuh logged over 400 '403' Web Errors from one IP Address. To onboard Wazuh data into Sentinel please view: https://github.com/wazuh/wazuh-documentation/blob/master/source/azure/monitoring%20activity.rst
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
