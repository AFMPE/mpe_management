resource "my_alert_rule" "rule_230" {
  name = "Squid proxy events for ToR proxies"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
let DomainList = dynamic(["tor2web.org", "tor2web.com", "torlink.co", "onion.to", "onion.ink", "onion.cab", "onion.nu", "onion.link", 
"onion.it", "onion.city", "onion.direct", "onion.top", "onion.casa", "onion.plus", "onion.rip", "onion.dog", "tor2web.fi", 
"tor2web.blutmagie.de", "onion.sh", "onion.lu", "onion.pet", "t2w.pw", "tor2web.ae.org", "tor2web.io", "tor2web.xyz", "onion.lt", 
"s1.tor-gateways.de", "s2.tor-gateways.de", "s3.tor-gateways.de", "s4.tor-gateways.de", "s5.tor-gateways.de", "hiddenservice.net"]);
Syslog
| where ProcessName contains "squid"
| extend URL = extract("(([A-Z]+ [a-z]{4,5}:\\/\\/)|[A-Z]+ )([^ :]*)",3,SyslogMessage), 
        SourceIP = extract("([0-9]+ )(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3}))",2,SyslogMessage), 
        Status = extract("(TCP_(([A-Z]+)(_[A-Z]+)*)|UDP_(([A-Z]+)(_[A-Z]+)*))",1,SyslogMessage), 
        HTTP_Status_Code = extract("(TCP_(([A-Z]+)(_[A-Z]+)*)|UDP_(([A-Z]+)(_[A-Z]+)*))/([0-9]{3})",8,SyslogMessage),
        User = extract("(CONNECT |GET )([^ ]* )([^ ]+)",3,SyslogMessage),
        RemotePort = extract("(CONNECT |GET )([^ ]*)(:)([0-9]*)",4,SyslogMessage),
        Domain = extract("(([A-Z]+ [a-z]{4,5}:\\/\\/)|[A-Z]+ )([^ :\\/]*)",3,SyslogMessage),
        Bytes = toint(extract("([A-Z]+\\/[0-9]{3} )([0-9]+)",2,SyslogMessage)),
        contentType = extract("([a-z/]+$)",1,SyslogMessage)
| extend TLD = extract("\\.[a-z]*$",0,Domain)
| where HTTP_Status_Code == "200"
| where Domain contains "."
| where Domain has_any (DomainList)
| extend timestamp = TimeGenerated, URLCustomEntity = URL, IPCustomEntity = SourceIP, AccountCustomEntity = User
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
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = URLCustomEntity
    }
  }
  tactics = ['CommandAndControl']
  techniques = ['T1008', 'T1090']
  display_name = Squid proxy events for ToR proxies
  description = <<EOT
Check for Squid proxy events associated with common ToR proxies. This query presumes the default squid log format is being used.
http://www.squid-cache.org/Doc/config/access_log/
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
