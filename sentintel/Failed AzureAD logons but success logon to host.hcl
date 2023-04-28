resource "my_alert_rule" "rule_64" {
  name = "Failed AzureAD logons but success logon to host"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
//Adjust this threshold to fit the environment
let signin_threshold = 5;
//Make a list of all IPs with failed signins to AAD above our threshold
let aadFunc = (tableName:string){
let suspicious_signins =
table(tableName)
| where ResultType !in ("0", "50125", "50140")
| where IPAddress !in ('127.0.0.1', '::1')
| summarize count() by IPAddress
| where count_ > signin_threshold
| summarize make_set(IPAddress);
//See if any of these IPs have sucessfully logged into *nix hosts
let linux_logons =
Syslog
| where Facility contains "auth" and ProcessName != "sudo"
| where SyslogMessage has "Accepted"
| extend SourceIP = extract("(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.(([0-9]{1,3})))",1,SyslogMessage)
| where SourceIP in (suspicious_signins)
| extend Reason = "Multiple failed AAD logins from IP address"
| project TimeGenerated, Computer, HostIP, IpAddress = SourceIP, SyslogMessage, Facility, ProcessName, Reason;
//See if any of these IPs have sucessfully logged into Windows hosts
let win_logons = (union isfuzzy=true
(SecurityEvent
| where EventID == 4624
| where LogonType in (10, 7, 3)
| where IpAddress != "-"
| where IpAddress in (suspicious_signins)
| extend Reason = "Multiple failed AAD logins from IP address"
| project TimeGenerated, Account, AccountType, Computer, Activity, EventID, LogonProcessName, IpAddress, LogonTypeName, TargetUserSid, Reason
),
(WindowsEvent
| where EventID == 4624 and has_any_ipv4(EventData, toscalar(suspicious_signins))
| extend LogonType = tostring(EventData.LogonType)
| where LogonType in (10, 7, 3)
| extend  IpAddress = tostring(EventData.IpAddress)
| where IpAddress != "-"
| where IpAddress in (suspicious_signins)
| extend Reason = "Multiple failed AAD logins from IP address"
| extend Activity = "4624 - An account was successfully logged on."
| extend Account =  strcat(tostring(EventData.TargetDomainName),"\\", tostring(EventData.TargetUserName))
| extend TargetUserSid = tostring(EventData.TargetUserSid)
| extend TargetAccount = strcat(EventData.TargetDomainName,"\\", EventData.TargetUserName)
| extend AccountType =case(Account endswith "$" or TargetUserSid in ("S-1-5-18", "S-1-5-19", "S-1-5-20"), "Machine", isempty(TargetUserSid), "", "User")
| extend LogonProcessName = tostring(EventData.LogonProcessName)
| project TimeGenerated, Account, AccountType, Computer, Activity, EventID, LogonProcessName, IpAddress, TargetUserSid, Reason
)
);
union isfuzzy=true linux_logons,win_logons
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, IPCustomEntity = IpAddress, HostCustomEntity = Computer
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
  tactics = ['InitialAccess', 'CredentialAccess']
  techniques = ['T1078', 'T1110']
  display_name = Failed AzureAD logons but success logon to host
  description = <<EOT
Identifies a list of IP addresses with a minimum number (default of 5) of failed logon attempts to Azure Active Directory.
Uses that list to identify any successful remote logons to hosts from these IPs within the same timeframe.
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
