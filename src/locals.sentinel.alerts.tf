# ## The following locals are usd to define the Sentinel Alert rules
locals {
  alert_rules = { 
    "AAD_No_Password_Expiry" = {
    query_frequency      = "P1D"
    query_period         = "P1D"
    severity             = "Low"

    query                = <<EOF
      union isfuzzy=true 
      (
      SecurityEvent
      | where EventID == 4738
      // 2089 value indicates the Don't Expire Password value has been set
      | where UserAccountControl has "%%2089" 
      | extend Value_2089 = iff(UserAccountControl has "%%2089","'Don't Expire Password' - Enabled", "Not Changed")
      // 2050 indicates that the Password Not Required value is NOT set, this often shows up at the same time as a 2089 and is the recommended value.  This value may not be in the event. 
      | extend Value_2050 = iff(UserAccountControl has "%%2050","'Password Not Required' - Disabled", "Not Changed")
      // If value %%2082 is present in the 4738 event, this indicates the account has been configured to logon WITHOUT a password. Generally you should only see this value when an account is created and only in Event 4720: Account Creation Event.  
      | extend Value_2082 = iff(UserAccountControl has "%%2082","'Password Not Required' - Enabled", "Not Changed")
      | project StartTime = TimeGenerated, EventID, Activity, Computer, TargetAccount, TargetSid, AccountType, UserAccountControl, Value_2089, Value_2050, Value_2082, SubjectAccount
      | extend timestamp = StartTime, AccountCustomEntity = TargetAccount, HostCustomEntity = Computer
      ),
      (
      WindowsEvent
      | where EventID == 4738 and EventData has '2089'
      // 2089 value indicates the Don't Expire Password value has been set
      | extend UserAccountControl = tostring(EventData.UserAccountControl)
      | where UserAccountControl has "%%2089" 
      | extend Value_2089 = iff(UserAccountControl has "%%2089","'Don't Expire Password' - Enabled", "Not Changed")
      // 2050 indicates that the Password Not Required value is NOT set, this often shows up at the same time as a 2089 and is the recommended value.  This value may not be in the event. 
      | extend Value_2050 = iff(UserAccountControl has "%%2050","'Password Not Required' - Disabled", "Not Changed")
      // If value %%2082 is present in the 4738 event, this indicates the account has been configured to logon WITHOUT a password. Generally you should only see this value when an account is created and only in Event 4720: Account Creation Event.  
      | extend Value_2082 = iff(UserAccountControl has "%%2082","'Password Not Required' - Enabled", "Not Changed")
      | extend Activity="4738 - A user account was changed."
      | extend TargetAccount = strcat(EventData.TargetDomainName,"\\", EventData.TargetUserName)
      | extend TargetSid = tostring(EventData.TargetSid)
      | extend SubjectAccount = strcat(EventData.SubjectDomainName,"\\", EventData.SubjectUserName)
      | extend SubjectUserSid = tostring(EventData.SubjectUserSid)
      | extend AccountType=case(SubjectAccount endswith "$" or SubjectUserSid in ("S-1-5-18", "S-1-5-19", "S-1-5-20"), "Machine", isempty(SubjectUserSid), "", "User")
      | project StartTime = TimeGenerated, EventID, Activity, Computer, TargetAccount, TargetSid, AccountType, UserAccountControl, Value_2089, Value_2050, Value_2082, SubjectAccount
      | extend timestamp = StartTime, AccountCustomEntity = TargetAccount, HostCustomEntity = Computer
      )
      EOF
    
  
    entity_mappings = [
      {
        entity_type = "Account"
        identifier = "FullName"
        field_name = "AccountCustomEntity"
         
      },
      {
        entity_type = "Host"
        identifier = "FullName"
        field_name = "HostCustomEntity"
          }
          
    ]

    tactics              = ["Persistence"]
    techniques           = ["T1098"]

    display_name = "AAD_No_Password_Expiry"
    description = <<EOT
Identifies whenever a user account has the setting "Password Never Expires" in the user account properties selected.
This is indicated in Security event 4738 in the EventData item labeled UserAccountControl with an included value of %%2089.
%%2089 resolves to "Don't Expire Password - Enabled".
EOT

    enabled = true
    create_incident = true
    grouping_enabled = true
    reopen_closed_incidents = true
    lookback_duration = "P1D"
    entity_matching_method = "AllEntities"
    group_by_entities = []
    group_by_alert_details = ["Severity"]
    suppression_duration = "P1D"
    suppression_enabled  = true
    event_grouping = "SingleAlert"
  }, # End Alert

  "Malicious_Web" = {
    query_frequency      = "P1D"
    query_period         = "P1D"
    severity             = "Medium"

    query                = <<EOF
let queryperiod = 1d;
let mode = 'Blocked';
let successCode = dynamic(['200', '101','204', '400','504','304','401','500']);
let sessionBin = 30m;
AzureDiagnostics
| where TimeGenerated > ago(queryperiod)
| where Category == 'ApplicationGatewayFirewallLog' and action_s == mode
| sort by hostname_s asc, clientIp_s asc, TimeGenerated asc
| extend SessionBlockedStarted = row_window_session(TimeGenerated, queryperiod, 10m, ((clientIp_s != prev(clientIp_s)) or (hostname_s != prev(hostname_s))))
| summarize SessionBlockedEnded = max(TimeGenerated), SessionBlockedCount = count() by hostname_s, clientIp_s, SessionBlockedStarted
| extend TimeKey = range(bin(SessionBlockedStarted, sessionBin), bin(SessionBlockedEnded, sessionBin), sessionBin)
| mv-expand TimeKey to typeof(datetime)
| join kind = inner(
    AzureDiagnostics
    | where TimeGenerated > ago(queryperiod)
    | where Category == 'ApplicationGatewayAccessLog' and (isempty(httpStatus_d) or httpStatus_d in (successCode))
    | extend TimeKey = bin(TimeGenerated, sessionBin)
) on TimeKey, $left.hostname_s == $right.host_s, $left.clientIp_s == $right.clientIP_s
| where TimeGenerated between (SessionBlockedStarted..SessionBlockedEnded)
| extend
    originalRequestUriWithArgs_s = column_ifexists("originalRequestUriWithArgs_s", ""),
    serverStatus_s = column_ifexists("serverStatus_s", "")
| summarize
    SuccessfulAccessCount = count(),
    UserAgents = make_set(userAgent_s, 250),
    RequestURIs = make_set(requestUri_s, 250),
    OriginalRequestURIs = make_set(originalRequestUriWithArgs_s, 250),
    SuccessCodes = make_set(httpStatus_d, 250),
    SuccessCodes_BackendServer = make_set(serverStatus_s, 250),
    take_any(SessionBlockedEnded, SessionBlockedCount)
    by hostname_s, clientIp_s, SessionBlockedStarted
| where SessionBlockedCount > SuccessfulAccessCount
| extend timestamp = SessionBlockedStarted, IPCustomEntity = clientIp_s
| extend BlockvsSuccessRatio = SessionBlockedCount/toreal(SuccessfulAccessCount)
| sort by BlockvsSuccessRatio desc, timestamp asc
| project-reorder SessionBlockedStarted, SessionBlockedEnded, hostname_s, clientIp_s, SessionBlockedCount, SuccessfulAccessCount, BlockvsSuccessRatio, SuccessCodes, RequestURIs, OriginalRequestURIs, UserAgents
EOF
    
  
    entity_mappings = [
      {
        entity_type = "IP"
        identifier = "Address"
        field_name = "IPCustomEntity"
         
      } 
    ]

    tactics              = ["InitialAccess"]
    techniques           = ["T1190"]

    display_name = "AAD_No_Password_Expiry"
    description = <<EOT
Detects unobstructed Web Application Firewall (WAF) activity in sessions where the WAF blocked incoming requests by computing the 
ratio between blocked requests and unobstructed WAF requests in these sessions (BlockvsSuccessRatio metric). A high ratio value for 
a given client IP and hostname calls for further investigation of the WAF data in that session, due to the significantly high number 
of blocked requests and a few unobstructed logs which may be malicious but have passed undetected through the WAF. The successCode 
variable defines what the detection thinks is a successful status code, and should be altered to fit the environment.
EOT

    enabled = true
    create_incident = true
    grouping_enabled = true
    reopen_closed_incidents = true
    lookback_duration = "P1D"
    entity_matching_method = "AllEntities"
    group_by_entities = []
    group_by_alert_details = ["Severity"]
    suppression_duration = "P1D"
    suppression_enabled  = false
    event_grouping = "SingleAlert"
  }, # End Alert
  
  "User_Added_To_Admin_Grp" = {
    query_frequency      = "P1D"
    query_period         = "P1D"
    severity             = "Medium"

    query                = <<EOF
SecurityEvent
| where EventID == 4728
| where TargetUserName contains "Admin" 
or TargetUserName contains "admin"
| extend AccountCustomEntity = Account 
| extend HostCustomEntity = Computer

EOF
    
  
    entity_mappings = [
      {
        entity_type = "Account"
        identifier = "FullName"
        field_name = "AccountCustomEntity"
         
      },
      {
        entity_type = "Host"
        identifier = "FullName"
        field_name = "HostCustomEntity"
         
      } 
    ]

    tactics              = ["Persistence"]
    techniques           = ["T1098"]

    display_name = "AAD_No_Password_Expiry"
    description = <<EOT
'Detects When user is added to a domain group that contains the word admin (Enterprise Admins,Domain Admins,DNS Admins)'

EOT

    enabled = true
    create_incident = true
    grouping_enabled = true
    reopen_closed_incidents = true
    lookback_duration = "P1D"
    entity_matching_method = "AllEntities"
    group_by_entities = []
    group_by_alert_details = ["Severity"]
    suppression_duration = "P1D"
    suppression_enabled  = false
    event_grouping = "SingleAlert"
  }, # End Alert

  
  } # End Alert Rules
} # End locals
 