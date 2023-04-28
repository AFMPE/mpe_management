resource "my_alert_rule" "rule_306" {
  name = "Failed logon attempts in authpriv"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let threshold = 15;
// Below pulls messages from syslog-authpriv logs where there was an authentication failure with an unknown user.
// IP address of system attempting logon is also extracted from the SyslogMessage field. Some of these messages
// are aggregated.
Syslog
| where Facility =~ "authpriv"
| where SyslogMessage has "authentication failure" and SyslogMessage has " uid=0"
| parse SyslogMessage with * "rhost=" RemoteIP
| project TimeGenerated, Computer, ProcessName, HostIP, RemoteIP, ProcessID
| join kind=innerunique (
    // Below pulls messages from syslog-authpriv logs that show each instance an unknown user tried to logon. 
    Syslog 
    | where Facility =~ "authpriv"
    | where SyslogMessage has "user unknown"
    | project Computer, HostIP, ProcessID
    ) on Computer, HostIP, ProcessID
// Count the number of failed logon attempts by External IP and internal machine
| summarize FirstLogonAttempt = min(TimeGenerated), LatestLogonAttempt = max(TimeGenerated), TotalLogonAttempts = count() by Computer, HostIP, RemoteIP
// Calculate the time between first and last logon attempt (AttemptPeriodLength)
| extend TimeBetweenLogonAttempts = LatestLogonAttempt - FirstLogonAttempt
| where TotalLogonAttempts >= threshold
| project FirstLogonAttempt, LatestLogonAttempt, TimeBetweenLogonAttempts, TotalLogonAttempts, SourceAddress = RemoteIP, DestinationHost = Computer, DestinationAddress = HostIP
| sort by DestinationHost asc nulls last
| extend timestamp = FirstLogonAttempt, HostCustomEntity = DestinationHost, IPCustomEntity = DestinationAddress
EOF
  entity_mapping {
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
  tactics = ['CredentialAccess']
  techniques = ['T1110']
  display_name = Failed logon attempts in authpriv
  description = <<EOT
Identifies failed logon attempts from unknown users in Syslog authpriv logs. The unknown user means the account that tried to log in 
isn't provisioned on the machine. A few hits could indicate someone attempting to access a machine they aren't authorized to access. 
If there are many of hits, especially from outside your network, it could indicate a brute force attack. 
Default threshold for logon attempts is 15.
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
