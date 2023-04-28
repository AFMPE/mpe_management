resource "my_alert_rule" "rule_217" {
  name = "Failed AWS Console logons but success logon to AzureAD"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
//Adjust this threshold to fit environment
let  signin_threshold = 5; 
//Make a list of IPs with failed AWS console logins
let aws_fails = AWSCloudTrail
| where EventName == "ConsoleLogin"
| extend LoginResult = tostring(parse_json(ResponseElements).ConsoleLogin) 
| where LoginResult != "Success"
| where SourceIpAddress != "127.0.0.1"
| summarize count() by SourceIpAddress
| where count_ >  signin_threshold
| summarize make_set(SourceIpAddress);
//See if any of those IPs have sucessfully logged into Azure AD.
SigninLogs
| where ResultType in ("0", "50125", "50140")
| where IPAddress in (aws_fails) 
| extend Reason = "Multiple failed AWS Console logins from IP address"
| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['InitialAccess', 'CredentialAccess']
  techniques = ['T1078', 'T1110']
  display_name = Failed AWS Console logons but success logon to AzureAD
  description = <<EOT
Identifies a list of IP addresses with a minimum numbe(default of 5) of failed logon attempts to AWS Console.
Uses that list to identify any successful Azure Active Directory logons from these IPs within the same timeframe.
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
