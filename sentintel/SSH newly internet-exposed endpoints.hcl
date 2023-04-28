resource "my_alert_rule" "rule_72" {
  name = "SSH newly internet-exposed endpoints"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P7D
  severity = Medium
  query = <<EOF
let PrivateIPregex = @'^127\.|^10\.|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.|^192\.168\.'; 
let avgthreshold = 0;
let probabilityLimit = 0.01;
let ssh_logins = Syslog
| where TimeGenerated >= ago(7d)
| where Facility contains "auth" and ProcessName != "sudo"
| where SyslogMessage has "Accepted"
| extend SourceIP = extract("(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.(([0-9]{1,3})))",1,SyslogMessage) 
| where isnotempty(SourceIP)
| extend ipType = iff(SourceIP matches regex PrivateIPregex,"private" ,"public" );
ssh_logins 
| summarize privatecount=countif(ipType=="private"), publiccount=countif(ipType=="public") by HostName, HostIP, bin(EventTime, 1d)
| summarize 
publicIPLoginHistory  = make_list(pack('IPCount', publiccount,  'logon_time', EventTime)),
privateIPLoginHistory = make_list(pack('IPCount', privatecount, 'logon_time', EventTime)) by HostName, HostIP
| mv-apply publicIPLoginHistory = publicIPLoginHistory on
(
    order by todatetime(publicIPLoginHistory['logon_time']) asc
    | summarize publicIPLoginCountList=make_list(toint(publicIPLoginHistory['IPCount'])), publicAverage=avg(toint(publicIPLoginHistory['IPCount'])), publicStd=stdev(toint(publicIPLoginHistory['IPCount'])), maxPublicLoginCount=max(toint(publicIPLoginHistory['IPCount']))
)
| mv-apply privateIPLoginHistory = privateIPLoginHistory on
(
    order by todatetime(privateIPLoginHistory['logon_time']) asc
    | summarize privateIPLoginCountList=make_list(toint(privateIPLoginHistory['IPCount'])), privateAverage=avg(toint(privateIPLoginHistory['IPCount'])), privateStd=stdev(toint(privateIPLoginHistory['IPCount']))
)
// Some logins from private IPs
| where privateAverage > avgthreshold
// There is a non-zero number of logins from public IPs
| where publicAverage > avgthreshold
// Approximate probability of seeing login from a public IP is < 1%
| extend probabilityPublic = publicAverage / (privateAverage + publicAverage)
| where probabilityPublic < probabilityLimit
// Today has the highest number of logins from public IPs that we've seen in the last week
| extend publicLoginCountToday = publicIPLoginCountList[-1]
| where publicLoginCountToday >= maxPublicLoginCount
| extend HostCustomEntity = HostName
// Optionally retrieve the original raw data for those logins that we've identified as potentially suspect
// | join kind=rightsemi (
//   ssh_logins
//  | where ipType == "public"
//  ) on HostName
EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = HostCustomEntity
    }
  }
  tactics = ['InitialAccess']
  techniques = ['T1133']
  display_name = SSH newly internet-exposed endpoints
  description = <<EOT
Endpoints with a history of sign-ins only from private IP addresses are accessed from a public IP address.
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = PT5M
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = None
    group_by_custom_details = None
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
