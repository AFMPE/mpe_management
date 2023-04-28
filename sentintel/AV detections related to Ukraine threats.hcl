resource "my_alert_rule" "rule_15" {
  name = "AV detections related to Ukraine threats"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = High
  query = <<EOF
let UA_threats = dynamic(["FoxBlade", "WhisperGate", "Lasainraw", "SonicVote"]);
  SecurityAlert
  | where ProviderName == "MDATP"
  | extend ThreatFamilyName = tostring(parse_json(ExtendedProperties).ThreatFamilyName)
  | where ThreatFamilyName in (UA_threats)
EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = CompromisedEntity
    }
  }
  tactics = ['Impact']
  techniques = ['T1485']
  display_name = AV detections related to Ukraine threats
  description = <<EOT
This query looks for Microsoft Defender AV detections for malware observed in relation to the war in Ukraine.
  Ref: https://msrc-blog.microsoft.com/2022/02/28/analysis-resources-cyber-threat-activity-ukraine/ 
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
