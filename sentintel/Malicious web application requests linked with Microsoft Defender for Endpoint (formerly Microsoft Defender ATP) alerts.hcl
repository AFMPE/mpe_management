resource "my_alert_rule" "rule_67" {
  name = "Malicious web application requests linked with Microsoft Defender for Endpoint (formerly Microsoft Defender ATP) alerts"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = P7D
  severity = Medium
  query = <<EOF
let alertTimeWindow = 1h;
let logTimeWindow = 7d;
// Define script extensions that suit your web application environment - a sample are provided below
let scriptExtensions = dynamic([".php", ".jsp", ".js", ".aspx", ".asmx", ".asax", ".cfm", ".shtml"]); 
let alertData = materialize(SecurityAlert 
| where TimeGenerated > ago(alertTimeWindow) 
| where ProviderName == "MDATP" 
// Parse and expand the alert JSON 
| extend alertData = parse_json(Entities) 
| mvexpand alertData);
let fileData = alertData
// Extract web script files from MDATP alerts - our malicious web scripts - candidate webshells
| where alertData.Type =~ "file" 
| where alertData.Name has_any(scriptExtensions) 
| extend FileName = tostring(alertData.Name), Directory = tostring(alertData.Directory);
let hostData = alertData
// Extract server details from alerts and map to alert id
| where alertData.Type =~ "host"
| project HostName = tostring(alertData.HostName), DnsDomain = tostring(alertData.DnsDomain), SystemAlertId
| distinct HostName, DnsDomain, SystemAlertId;
// Join the files on their impacted servers
let webshellData = fileData
| join kind=inner (hostData) on SystemAlertId 
| project TimeGenerated, FileName, Directory, HostName, DnsDomain;
webshellData
| join (  
// Find requests that were made to this file on the impacted server in the W3CIISLog table 
W3CIISLog  
| where TimeGenerated > ago(logTimeWindow) 
// Restrict to accesses to script extensions 
| where csUriStem has_any(scriptExtensions)
| extend splitUriStem = split(csUriStem, "/")  
| extend FileName = splitUriStem[-1], HostName = sComputerName
// Summarize potential attacker activity
| summarize count(), StartTime=min(TimeGenerated), EndTime=max(TimeGenerated), RequestUserAgents=make_set(csUserAgent), ReqestMethods=make_set(csMethod), RequestStatusCodes=make_set(scStatus), RequestCookies=make_set(csCookie), RequestReferers=make_set(csReferer), RequestQueryStrings=make_set(csUriQuery) by AttackerIP=cIP, SiteName=sSiteName, ShellLocation=csUriStem, tostring(FileName), HostName  
) on FileName, HostName
| project StartTime, EndTime, AttackerIP, RequestUserAgents, HostName, SiteName, ShellLocation, ReqestMethods, RequestStatusCodes, RequestCookies, RequestReferers, RequestQueryStrings, RequestCount = count_
// Expose the attacker ip address as a custom entity
| extend timestamp=StartTime, IPCustomEntity = AttackerIP, HostCustomEntity = HostName
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
  tactics = ['Persistence']
  techniques = ['T1505']
  display_name = Malicious web application requests linked with Microsoft Defender for Endpoint (formerly Microsoft Defender ATP) alerts
  description = <<EOT
Takes Microsoft Defender for Endpoint (formerly Microsoft Defender ATP) alerts where web scripts are present in the evidence and correlates with requests made to those scripts
in the WCSIISLog to surface new alerts for potentially malicious web request activity.
The lookback for alerts is set to 1h and the lookback for W3CIISLogs is set to 7d. A sample set of popular web script extensions
has been provided in scriptExtensions that should be tailored to your environment.
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
