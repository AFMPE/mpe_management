resource "my_alert_rule" "rule_292" {
  name = "Palo Alto - possible internal to external port scanning"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Low
  query = <<EOF
let PortCountThreshold = 3; // How many ports need to be hit to trigger
let IPCountThreshold = 5; // How many unique IPs need be hit to trigger
CommonSecurityLog 
| where isnotempty(DestinationPort) and DeviceAction !in ("reset-both", "deny") 
// filter out common usage ports. Add ports that are legitimate for your environment
| where DestinationPort !in ("443", "53", "389", "80", "0", "880", "8888", "8080")
| where ApplicationProtocol == "incomplete" 
// filter out IANA ephemeral or negotiated ports as per https://en.wikipedia.org/wiki/Ephemeral_port
| where DestinationPort !between (toint(49512) .. toint(65535)) 
| where Computer != "" 
| where not(DestinationIP matches regex @"(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)")
| where SourceIP matches regex @"(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)"
// Filter out any graceful reset reasons of AGED OUT which occurs when a TCP session closes with a FIN due to aging out. 
| where AdditionalExtensions !has "reason=aged-out" 
// Filter out any TCP FIN which occurs when a TCP FIN is used to gracefully close half or both sides of a connection.
| where AdditionalExtensions !has "reason=tcp-fin" 
// Uncomment one of the following where clauses to trigger on specific TCP reset reasons
// See Palo Alto article for details - https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClUvCAK
// TCP RST-server - Occurs when the server sends a TCP reset to the client
// | where AdditionalExtensions has "reason=tcp-rst-from-server"  
// TCP RST-client - Occurs when the client sends a TCP reset to the server
// | where AdditionalExtensions has "reason=tcp-rst-from-client"  
| extend reason = tostring(split(AdditionalExtensions, ";")[3])
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), count() by DeviceName, SourceUserID, SourceIP, ApplicationProtocol, reason, DestinationPort, Protocol, DeviceVendor, DeviceProduct, DeviceAction, DestinationIP
| where count_ >= 10
| summarize StartTimeUtc = min(StartTimeUtc), EndTimeUtc = max(EndTimeUtc), makeset(DestinationIP), makeset(DestinationPort), totalcount = sum(count_) by DeviceName, SourceUserID, SourceIP, ApplicationProtocol, reason, Protocol, DeviceVendor, DeviceProduct, DeviceAction
| extend DestinationPortCount = iif(array_length(set_DestinationPort) >= PortCountThreshold, "true", "false"), DestinationIPCount = iif(array_length(set_DestinationIP) >= IPCountThreshold, "true", "false")
| where DestinationPortCount == "true" and DestinationIPCount == "true"
| extend timestamp = StartTimeUtc, IPCustomEntity = SourceIP, AccountCustomEntity = SourceUserID, HostCustomEntity = DeviceName
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
  tactics = ['Discovery']
  techniques = ['T1046']
  display_name = Palo Alto - possible internal to external port scanning
  description = <<EOT
Identifies a list of internal Source IPs that have triggered 10 or more non-graceful tcp server resets from one or more Destination IPs which 
results in an "ApplicationProtocol = incomplete" designation. The server resets coupled with an "Incomplete" ApplicationProtocol designation can be an indication 
of internal to external port scanning or probing attack. 
References: https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClUvCAK and
https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClTaCAK
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
