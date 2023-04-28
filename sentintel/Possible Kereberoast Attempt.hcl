resource "my_alert_rule" "rule_279" {
  name = "Possible Kereberoast Attempt"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
SecurityEvent
| where EventID == 4769  
| where ServiceName != "krbtgt" 
| where ServiceName !endswith "$" 
| where EventData contains "0x17" 
| where EventData contains "<Data Name=\"Status\">0x0</Data>"
| extend AccountCustomEntity = Account 
| extend HostCustomEntity = Computer

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
  tactics = ['CredentialAccess']
  techniques = ['T1558']
  display_name = Possible Kereberoast Attempt
  description = <<EOT
'Service principal names (SPNs) are used to uniquely identify each instance of a Windows service. To enable authentication, Kerberos requires that SPNs be associated with at least one service logon account 
(an account specifically tasked with running a service Adversaries possessing a valid Kerberos ticket-granting ticket (TGT) 
may request one or more Kerberos ticket-granting service (TGS) service tickets for any SPN from a domain controller (DC).
Portions of these tickets may be encrypted with the RC4 algorithm, meaning the Kerberos 5 TGS-REP etype 23 hash of the service account 
associated with the SPN is used as the private key and is thus vulnerable to offline Brute Force attacks that may expose plaintext credentials.
This same attack could be executed using service tickets captured from network traffic.
Cracked hashes may enable Persistence, Privilege Escalation, and Lateral Movement via access to Valid Accounts.'

EOT
  enabled = False
  create_incident = True
  grouping_configuration {
    enabled = True
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5M
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
