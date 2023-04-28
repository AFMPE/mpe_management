resource "my_alert_rule" "rule_313" {
  name = "Malformed user agent"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
(union isfuzzy=true
(OfficeActivity | where UserAgent != ""),
(OfficeActivity
| where RecordType in ("AzureActiveDirectory", "AzureActiveDirectoryStsLogon")
| extend OperationName = Operation
| parse ExtendedProperties with * 'User-Agent\\":\\"' UserAgent2 '\\' *
| parse ExtendedProperties with * 'UserAgent",      "Value": "' UserAgent1 '"' *
| where isnotempty(UserAgent1) or isnotempty(UserAgent2)
| extend UserAgent = iff( RecordType == 'AzureActiveDirectoryStsLogon', UserAgent1, UserAgent2)
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserAgent, SourceIP = ClientIP, Account = UserId, Type, RecordType, Operation
),
(AzureDiagnostics
| where ResourceType =~ "APPLICATIONGATEWAYS" 
| where OperationName =~ "ApplicationGatewayAccess" 
| extend ClientIP = columnifexists("clientIP_s", "None"), UserAgent = columnifexists("userAgent_s", "None")
| where UserAgent != '-'
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserAgent, SourceIP = ClientIP,  requestUri_s, httpMethod_s, host_s, requestQuery_s, Type
),
(
W3CIISLog
| where isnotempty(csUserAgent)
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserAgent = csUserAgent, SourceIP = cIP, Account = csUserName, Type, sSiteName, csMethod, csUriStem
),
(
AWSCloudTrail
| where isnotempty(UserAgent)
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserAgent, SourceIP = SourceIpAddress, Account = UserIdentityUserName, Type, EventSource, EventName
),
(SigninLogs
| where isnotempty(UserAgent)
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserAgent, SourceIP = IPAddress, Account = UserPrincipalName, Type, OperationName, tostring(LocationDetails), tostring(DeviceDetail), AppDisplayName, ClientAppUsed
),
(AADNonInteractiveUserSignInLogs 
| where isnotempty(UserAgent)
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserAgent, SourceIP = IPAddress, Account = UserPrincipalName, Type, OperationName, tostring(LocationDetails), tostring(DeviceDetail), AppDisplayName, ClientAppUsed
)
)
// Likely artefact of hardcoding
| where UserAgent startswith "User" or UserAgent startswith '\"'
// Incorrect casing
or (UserAgent startswith "Mozilla" and not(UserAgent containscs "Mozilla"))
// Incorrect casing
or UserAgent containscs  "(Compatible;"
// Missing MSIE version
or UserAgent matches regex @"MSIE\s?;"
// Incorrect spacing around MSIE version
or UserAgent matches regex  @"MSIE(?:\d|.{1,5}?\d\s;)"
| extend timestamp = StartTime, IPCustomEntity = SourceIP, AccountCustomEntity = Account
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
  tactics = ['InitialAccess', 'CommandAndControl', 'Execution']
  techniques = ['T1189', 'T1071', 'T1203']
  display_name = Malformed user agent
  description = <<EOT
Malware authors will sometimes hardcode user agent string values when writing the network communication component of their malware.
Malformed user agents can be an indication of such malware.
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
