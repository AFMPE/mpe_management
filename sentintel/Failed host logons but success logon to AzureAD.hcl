resource "my_alert_rule" "rule_11" {
  name = "Failed host logons but success logon to AzureAD"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
//Adjust this threshold to fit environment
let signin_threshold = 5; 
//Make a list of IPs with failed Windows host logins above threshold
let win_fails = 
SecurityEvent
| where EventID == 4625
| where LogonType in (10, 7, 3)
| where IpAddress != "-"
| summarize count() by IpAddress
| where count_ > signin_threshold
| summarize make_list(IpAddress);
let wef_fails =
WindowsEvent
| where EventID == 4625
| extend LogonType = tostring(EventData.LogonType)
| where LogonType in (10, 7, 3)
| extend IpAddress = tostring(EventData.IpAddress)
| where IpAddress != "-"
| summarize count() by IpAddress
| where count_ > signin_threshold
| summarize make_list(IpAddress);
//Make a list of IPs with failed *nix host logins above threshold
let nix_fails = 
Syslog
| where Facility contains 'auth' and ProcessName != 'sudo'
| extend SourceIP = extract("(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.(([0-9]{1,3})))",1,SyslogMessage)
| where SourceIP != "" and SourceIP != "127.0.0.1"
| summarize count() by SourceIP
| where count_ > signin_threshold
| summarize make_list(SourceIP);
//See if any of the IPs with failed host logins hve had a sucessful Azure AD login
let aadFunc = (tableName:string){
table(tableName)
| where ResultType !in ("0", "50125", "50140")
| where IPAddress in (win_fails) or IPAddress in (nix_fails) or IPAddress in (wef_fails)
| extend Reason=  "Multiple failed host logins from IP address with successful Azure AD login"
| extend timstamp = TimeGenerated, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress, Type = Type
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
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
  display_name = Failed host logons but success logon to AzureAD
  description = <<EOT
Identifies a list of IP addresses with a minimum number(default of 5) of failed logon attempts to remote hosts.
Uses that list to identify any successful logons to Azure Active Directory from these IPs within the same timeframe.
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
