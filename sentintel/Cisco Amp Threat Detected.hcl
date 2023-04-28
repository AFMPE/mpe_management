resource "my_alert_rule" "rule_2" {
  name = "Cisco Amp Threat Detected"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT15M
  query_period = PT15M
  severity = Medium
  query = <<EOF
CiscoSecureEndpoint_CL
| where event_type_s has_any ("Threat Detected", "Threat Quarantined")
| project TimeGenerated, Severity = severity_s, Computer = computer_hostname_s, Account = computer_user_s, Activity = event_type_s, Description = detection_s, FileName = file_file_name_s, SHA1 = file_identity_sha1_s, FilePath = file_file_path_s, ParentFileName = file_parent_file_name_s, ParentSHA1 = file_parent_identity_sha1_s, ParentProcessID = file_parent_process_id_d, ExternalIP = computer_external_ip_s, InternalIP1 = parse_json(parse_json(computer_network_addresses_s)[0]).ip, InternalIP2 = parse_json(parse_json(computer_network_addresses_s)[1]).ip
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
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = InternalIP1
    }
    entity_type = FileHash
    field_mappings {
      identifier = Value
      column_name = SHA1
    }
    entity_type = File
    field_mappings {
      identifier = Name
      column_name = FileName
      identifier = Directory
      column_name = FilePath
    }
  }
  tactics = ['Discovery', 'Impact']
  techniques = ['T1046', 'T1498']
  display_name = Cisco Amp Threat Detected
  description = <<EOT
Alerts when Cisco Amp detects threats on an endpoint. 
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
