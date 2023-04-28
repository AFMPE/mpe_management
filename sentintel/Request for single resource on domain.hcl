resource "my_alert_rule" "rule_316" {
  name = "Request for single resource on domain"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
let scriptExtensions = dynamic([".php", ".aspx", ".asp", ".cfml"]);
//The number of URI's seen to be suspicious, higher = less likely to be suspicious
let uriThreshold = 1;
CommonSecurityLog
// Only look at connections that were allowed through the web proxy
| where DeviceVendor =~ "Zscaler" and DeviceAction =~ "Allowed"
// Only look where some data was exchanged.
| where SentBytes > 0 and ReceivedBytes > 0
// Extract the Domain
| extend Domain = iff(countof(DestinationHostName,'.') >= 2, strcat(split(DestinationHostName,'.')[-2], '.',split(DestinationHostName,'.')[-1]), DestinationHostName)
| extend GetData=iff(RequestURL == "?", 1, 0)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), makelist(RequestURL), makelist(DestinationIP), makelist(SourceIP), numOfConnections = count(), make_set(RequestMethod), max(GetData), max(RequestContext) by Domain
// Determine the number of URIs that have been visited for the domain
| extend destinationURI = arraylength(list_RequestURL)
| where destinationURI <= uriThreshold
| where tostring(list_RequestURL) has_any(scriptExtensions)
//Remove matches with referer
| where max_RequestContext == ""
//Keep requests where data was trasferred either in a GET with parameters or a POST
| where set_RequestMethod in~ ("POST") or max_GetData == 1
//Defeat email click tracking, may increase FN's while decreasing FP's
| where list_RequestURL !has "click" and set_RequestMethod !has "GET"
| mvexpand list_RequestURL, list_DestinationIP
| extend RequestURL = tostring(list_RequestURL), DestinationIP = tostring(list_DestinationIP), ClientIP = tostring(list_SourceIP)
//Extend custom entitites for incidents
| extend timestamp = StartTimeUtc, IPCustomEntity = DestinationIP
| project-away list_RequestURL, list_DestinationIP, list_SourceIP, destinationURI, Domain, StartTimeUtc, EndTimeUtc, max_GetData, max_RequestContext
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['CommandAndControl']
  techniques = ['T1102', 'T1071']
  display_name = Request for single resource on domain
  description = <<EOT
This will look for connections to a domain where only a single file is requested, this is unusual as most modern web applications require additional recources. This type of activity is often assocaited with malware beaconing or tracking URL's delivered in emails. Developed for Zscaler but applicable to any outbound web logging.
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
