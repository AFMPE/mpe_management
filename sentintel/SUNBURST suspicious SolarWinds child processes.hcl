resource "my_alert_rule" "rule_123" {
  name = "SUNBURST suspicious SolarWinds child processes"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let excludeProcs = dynamic([@"\SolarWinds\Orion\APM\APMServiceControl.exe", @"\SolarWinds\Orion\ExportToPDFCmd.Exe", @"\SolarWinds.Credentials\SolarWinds.Credentials.Orion.WebApi.exe", @"\SolarWinds\Orion\Topology\SolarWinds.Orion.Topology.Calculator.exe", @"\SolarWinds\Orion\Database-Maint.exe", @"\SolarWinds.Orion.ApiPoller.Service\SolarWinds.Orion.ApiPoller.Service.exe", @"\Windows\SysWOW64\WerFault.exe"]);
DeviceProcessEvents
| where InitiatingProcessFileName =~ "solarwinds.businesslayerhost.exe"
| where not(ProcessCommandLine has_any ("SolarWinds.BusinessLayerHostx64.exe", "SolarWinds.Orion.Topology.Calculator.exe", "SolarWinds.Topology.Calculator.exe"))
| where not(FolderPath has_any (excludeProcs))
| extend timestamp = TimeGenerated, AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName), HostCustomEntity = DeviceName, AlgorithmCustomEntity = "MD5", FileHashCustomEntity = MD5
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
    entity_type = FileHash
    field_mappings {
      identifier = Algorithm
      column_name = AlgorithmCustomEntity
      identifier = Value
      column_name = FileHashCustomEntity
    }
  }
  tactics = ['Execution', 'Persistence']
  techniques = ['T1059', 'T1546']
  display_name = SUNBURST suspicious SolarWinds child processes
  description = <<EOT
Identifies suspicious child processes of SolarWinds.Orion.Core.BusinessLayer.dll that may be evidence of the SUNBURST backdoor
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f
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
