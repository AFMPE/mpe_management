resource "my_alert_rule" "rule_127" {
  name = "IP with multiple failed Azure AD logins successfully logs in to Palo Alto VPN"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
//Set a threshold of failed AAD signins from an IP address within 1 day above which we want to deem those logins suspicious.
let signin_threshold = 5; 
//Make a list of IPs with AAD signin failures above our threshold.
let aadFunc = (tableName: string) {
    let suspicious_signins = 
        table(tableName)
        | where ResultType !in ("0", "50125", "50140")
        //Exclude localhost addresses to reduce the chance of FPs
        | where IPAddress !in ("127.0.0.1", "::1")
        | extend Status = tostring(parse_json(Status).failureReason)
        | summarize make_set(Status), count() by IPAddress
        | where count_ > signin_threshold;
    suspicious_signins
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
let suspicious_signins = union isfuzzy=true aadSignin, aadNonInt;
//See if any of those IPs have sucessfully logged into PA VPNs during the same timeperiod
CommonSecurityLog
//Select only PA VPN sucessful logons
| where DeviceVendor == "Palo Alto Networks" and DeviceEventClassID == "globalprotect"
| where Message has "GlobalProtect gateway user authentication succeeded"
//Parse out the logon source IP from the Message field to match on
| extend SourceIP = extract("Login from: ([^,]+)", 1, Message) 
| where SourceIP in (suspicious_signins)
| join kind=leftouter (suspicious_signins | project IPAddress, set_Status) on $left.SourceIP == $right.IPAddress
| extend Reason = "Multiple failed AAD logins from SourceIP"
//Parse out other useful information from Message field
| extend User = extract('User name: ([^,]+)', 1, Message) 
| extend ClientOS = extract('Client OS version: ([^,\"]+)', 1, Message)
| extend Location = extract('Source region: ([^,]{2})', 1, Message)
| project TimeGenerated, Reason, SourceIP, User, ClientOS, Location, Message, DeviceName, ReceiptTime, DeviceVendor, DeviceEventClassID, Computer, FileName, FailureReason = set_Status
| extend AccountCustomEntity = User, IPCustomEntity = SourceIP, timestamp = TimeGenerated, HostCustomEntity = DeviceName
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
  display_name = IP with multiple failed Azure AD logins successfully logs in to Palo Alto VPN
  description = <<EOT
This query creates a list of IP addresses with a number failed login attempts to AAD 
above a set threshold.  It then looks for any successful Palo Alto VPN logins from any
of these IPs within the same timeframe.
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
