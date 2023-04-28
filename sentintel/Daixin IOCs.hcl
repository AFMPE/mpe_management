resource "my_alert_rule" "rule_170" {
  name = "Daixin IOCs"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let DFE=
(DeviceFileEvents
| where SHA256 has_any ("9E42E07073E03BDEA4CD978D9E7B44A9574972818593306BE1F3DCFDEE722238", "19ED36F063221E161D740651E6578D50E0D3CACEE89D27A6EBED4AB4272585BD", "54E3B5A2521A84741DC15810E6FED9D739EB8083CB1FE097CB98B345AF24E939","EC16E2DE3A55772F5DFAC8BF8F5A365600FAD40A244A574CBAB987515AA40CBF", "475D6E80CF4EF70926A65DF5551F59E35B71A0E92F0FE4DD28559A9DEBA60C28")
| where FolderPath has_any ("rclone-v1.59.2-windows-amd64\\git-log.txt", "rclone-v1.59.2-windows-amd64\\rclone.1", "rclone-v1.59.2-windows-amd64\\rclone.exe", "rclone-v1.59.2-windows-amd64\\README.html", "rclone-v1.59.2-windows-amd64\\README.txt")
|extend AccountCustomEntity = InitiatingProcessAccountUpn, HostCustomEntity = DeviceName
)
;
let DPE=
(DeviceProcessEvents
|where SHA256 has_any ("9E42E07073E03BDEA4CD978D9E7B44A9574972818593306BE1F3DCFDEE722238", "19ED36F063221E161D740651E6578D50E0D3CACEE89D27A6EBED4AB4272585BD", "54E3B5A2521A84741DC15810E6FED9D739EB8083CB1FE097CB98B345AF24E939","EC16E2DE3A55772F5DFAC8BF8F5A365600FAD40A244A574CBAB987515AA40CBF", "475D6E80CF4EF70926A65DF5551F59E35B71A0E92F0FE4DD28559A9DEBA60C28")
| where FolderPath has_any ("rclone-v1.59.2-windows-amd64\\git-log.txt", "rclone-v1.59.2-windows-amd64\\rclone.1", "rclone-v1.59.2-windows-amd64\\rclone.exe", "rclone-v1.59.2-windows-amd64\\README.html", "rclone-v1.59.2-windows-amd64\\README.txt")
| extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName
);
DFE
| union DPE
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
  tactics = ['Persistence']
  techniques = None
  display_name = Daixin IOCs
  description = <<EOT
'Identifies IOCs associated with the Daixin ransomware team'

EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
    reopen_closed_incident = False
    lookback_duration = P1D
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = P1D
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
